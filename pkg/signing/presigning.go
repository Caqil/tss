// Package signing - Presigning support for faster online phase
package signing

import (
	"crypto/hmac"
	"math/big"
	"sync"
	"time"

	"github.com/Caqil/mpc-tss/internal/security"
	"github.com/Caqil/mpc-tss/pkg/crypto/commitment"
	"github.com/Caqil/mpc-tss/pkg/crypto/curve"
	"github.com/Caqil/mpc-tss/pkg/crypto/rand"
	"github.com/Caqil/mpc-tss/pkg/keygen"
	"github.com/Caqil/mpc-tss/pkg/zk"
)

// PreSignature represents a pre-computed signature that can be used for fast signing
type PreSignature struct {
	// ID uniquely identifies this pre-signature
	ID []byte

	// R is the ephemeral public nonce point
	R *curve.Point

	// r is R.x mod n
	r *big.Int

	// k is the ephemeral secret nonce
	k *big.Int

	// kInv is k^-1 mod n for fast online signing
	kInv *big.Int

	// PartyID identifies which party created this
	PartyID int

	// CreatedAt is when this pre-signature was created
	CreatedAt time.Time

	// ExpiresAt is when this pre-signature expires
	ExpiresAt time.Time

	// used tracks if this pre-signature has been consumed
	used bool

	// mu protects concurrent access
	mu sync.Mutex
}

// PreSignaturePool manages a pool of pre-computed signatures
type PreSignaturePool struct {
	keyShare      *keygen.KeyShare
	preSignatures map[string]*PreSignature
	maxSize       int
	ttl           time.Duration
	mu            sync.RWMutex
}

// NewPreSignaturePool creates a new pre-signature pool
func NewPreSignaturePool(keyShare *keygen.KeyShare, maxSize int, ttl time.Duration) *PreSignaturePool {
	return &PreSignaturePool{
		keyShare:      keyShare,
		preSignatures: make(map[string]*PreSignature),
		maxSize:       maxSize,
		ttl:           ttl,
	}
}

// PreSignRound1Data contains data for presigning round 1
type PreSignRound1Data struct {
	PreSignID     []byte
	PartyID       int
	Commitment    []byte
	KProof        *zk.SchnorrProof
	CommitmentCtx []byte
}

// PreSignRound2Data contains data for presigning round 2
type PreSignRound2Data struct {
	PreSignID []byte
	PartyID   int
	R         *curve.Point
	Decommit  []byte
}

// GeneratePreSignatureRound1 generates round 1 data for presigning
func (t *ThresholdSigner) GeneratePreSignatureRound1() (*PreSignRound1Data, *round1State, error) {
	order := t.curve.Order()

	// Generate unique presignature ID
	preSignID, err := rand.GenerateRandomBytes(32)
	if err != nil {
		return nil, nil, err
	}

	// Generate ephemeral nonce k
	k, err := rand.GenerateRandomScalar(order)
	if err != nil {
		return nil, nil, err
	}

	// Compute R = k * G
	R, err := t.curve.ScalarBaseMult(k)
	if err != nil {
		security.SecureZero(k.Bytes())
		return nil, nil, err
	}

	// Validate R is on curve
	if !t.curve.IsOnCurve(R) {
		security.SecureZero(k.Bytes())
		return nil, nil, ErrInvalidNonce
	}

	// Create commitment context
	commitmentCtx := make([]byte, 0, 64)
	commitmentCtx = append(commitmentCtx, preSignID...)
	commitmentCtx = append(commitmentCtx, []byte("presign-v1")...)

	// Create hash commitment to R
	hashCommit, err := commitment.NewHashCommitment(R.Bytes(), commitmentCtx)
	if err != nil {
		security.SecureZero(k.Bytes())
		return nil, nil, err
	}

	// Create zero-knowledge proof of knowledge of k
	kProof, err := zk.ProveSchnorr(k, R, t.curve, commitmentCtx)
	if err != nil {
		security.SecureZero(k.Bytes())
		return nil, nil, err
	}

	// Store state
	state := &round1State{
		k:              k,
		gamma:          k,
		commitmentHash: hashCommit.GetCommitmentValue(),
		decommit:       hashCommit.Nonce,
	}

	return &PreSignRound1Data{
		PreSignID:     preSignID,
		PartyID:       t.partyID,
		Commitment:    hashCommit.GetCommitmentValue(),
		KProof:        kProof,
		CommitmentCtx: commitmentCtx,
	}, state, nil
}

// GeneratePreSignatureRound2 generates round 2 data for presigning
func (t *ThresholdSigner) GeneratePreSignatureRound2(
	preSignID []byte,
	state *round1State,
	round1Data []*PreSignRound1Data,
) (*PreSignRound2Data, map[int]*PreSignRound1Data, error) {
	if state == nil {
		return nil, nil, ErrMissingRound1Data
	}

	// Validate we have enough parties
	if len(round1Data) < t.threshold-1 {
		return nil, nil, ErrInsufficientParties
	}

	// Validate and store round 1 data
	seenParties := make(map[int]bool)
	seenParties[t.partyID] = true
	receivedData := make(map[int]*PreSignRound1Data)

	for _, data := range round1Data {
		// Validate party ID
		if data.PartyID == t.partyID {
			return nil, nil, ErrInvalidPartyID
		}

		if data.PartyID < 0 || data.PartyID >= t.keyShare.Parties {
			return nil, nil, ErrInvalidPartyID
		}

		// Check for duplicates
		if seenParties[data.PartyID] {
			return nil, nil, ErrDuplicateParty
		}
		seenParties[data.PartyID] = true

		// Validate pre-signature ID matches
		if !hmac.Equal(data.PreSignID, preSignID) {
			return nil, nil, ErrInvalidSessionID
		}

		receivedData[data.PartyID] = data
	}

	// Compute R = k * G for revealing
	R, err := t.curve.ScalarBaseMult(state.k)
	if err != nil {
		return nil, nil, err
	}

	return &PreSignRound2Data{
		PreSignID: preSignID,
		PartyID:   t.partyID,
		R:         R,
		Decommit:  state.decommit,
	}, receivedData, nil
}

// FinalizePreSignature finalizes a pre-signature after round 2
func (t *ThresholdSigner) FinalizePreSignature(
	preSignID []byte,
	state *round1State,
	round1Data map[int]*PreSignRound1Data,
	round2Data []*PreSignRound2Data,
) (*PreSignature, error) {
	if state == nil {
		return nil, ErrMissingRound1Data
	}

	// Validate we have matching round 2 data
	if len(round2Data) != len(round1Data) {
		return nil, ErrMissingRound2Data
	}

	// Verify all decommitments
	for _, data := range round2Data {
		// Get corresponding round 1 data
		round1, ok := round1Data[data.PartyID]
		if !ok {
			return nil, ErrInvalidPartyID
		}

		// Validate pre-signature ID
		if !hmac.Equal(data.PreSignID, preSignID) {
			return nil, ErrInvalidSessionID
		}

		// Verify commitment
		if !commitment.VerifyCommitmentToCurvePoint(round1.Commitment, data.R, data.Decommit, t.curve, round1.CommitmentCtx) {
			return nil, ErrCommitmentMismatch
		}

		// Verify zero-knowledge proof
		if !round1.KProof.Verify(data.R, round1.CommitmentCtx) {
			return nil, ErrInvalidProof
		}

		// Validate R is on curve
		if !t.curve.IsOnCurve(data.R) {
			return nil, ErrInvalidNonce
		}
	}

	// Compute combined R = sum of all party R values
	R, err := t.curve.ScalarBaseMult(state.k)
	if err != nil {
		return nil, err
	}

	for _, data := range round2Data {
		R, err = t.curve.Add(R, data.R)
		if err != nil {
			return nil, err
		}
	}

	// Extract r = R.x mod n
	order := t.curve.Order()
	r := new(big.Int).Mod(R.X, order)

	// Ensure r is non-zero
	if r.Sign() == 0 {
		return nil, ErrInvalidR
	}

	// Compute k^-1 mod n for fast online signing
	kInv := security.ConstantTimeModInv(state.k, order)
	if kInv == nil {
		return nil, ErrInvalidNonce
	}

	return &PreSignature{
		ID:        preSignID,
		R:         R,
		r:         r,
		k:         state.k,
		kInv:      kInv,
		PartyID:   t.partyID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour), // Default 24h expiry
		used:      false,
	}, nil
}

// SignWithPreSignature performs fast online signing using a pre-signature
// s = k^-1 * (H(m) + r*x) mod n
func (t *ThresholdSigner) SignWithPreSignature(messageHash []byte, preSign *PreSignature) (*Signature, error) {
	if len(messageHash) != 32 {
		return nil, ErrInvalidMessage
	}

	if preSign == nil {
		return nil, ErrInvalidPreSignature
	}

	// Mark as used atomically
	preSign.mu.Lock()
	defer preSign.mu.Unlock()

	if preSign.used {
		return nil, ErrPreSignatureAlreadyUsed
	}

	// Check expiry
	if time.Now().After(preSign.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	order := t.curve.Order()
	m := new(big.Int).SetBytes(messageHash)

	// Compute s = k^-1 * (m + r*x) mod n
	// This is much faster than the multi-round protocol

	// r*x
	rx := security.ConstantTimeModMul(preSign.r, t.keyShare.Share, order)

	// m + r*x
	mrx := security.ConstantTimeModAdd(m, rx, order)

	// k^-1 * (m + r*x)
	s := security.ConstantTimeModMul(preSign.kInv, mrx, order)

	// Apply low-s normalization (BIP 62)
	halfOrder := new(big.Int).Rsh(order, 1)
	if s.Cmp(halfOrder) > 0 {
		s = new(big.Int).Sub(order, s)
	}

	signature := &Signature{
		R: preSign.r,
		S: s,
	}

	// Verify the signature before returning
	if !Verify(t.keyShare.PublicKey, messageHash, signature, t.curve) {
		return nil, ErrInvalidSignature
	}

	// Mark as used
	preSign.used = true

	// Securely zero the ephemeral key
	security.SecureZero(preSign.k.Bytes())

	return signature, nil
}

// Add adds a pre-signature to the pool
func (pool *PreSignaturePool) Add(preSign *PreSignature) error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// Check if pool is full
	if len(pool.preSignatures) >= pool.maxSize {
		// Evict oldest expired pre-signature
		pool.evictOldest()
	}

	// Check if still full after eviction
	if len(pool.preSignatures) >= pool.maxSize {
		return ErrInsufficientParties
	}

	pool.preSignatures[string(preSign.ID)] = preSign
	return nil
}

// Get retrieves an unused pre-signature from the pool
func (pool *PreSignaturePool) Get() (*PreSignature, error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// Find first unused, non-expired pre-signature
	now := time.Now()

	for id, preSign := range pool.preSignatures {
		preSign.mu.Lock()

		if !preSign.used && now.Before(preSign.ExpiresAt) {
			preSign.mu.Unlock()
			return preSign, nil
		}

		// Clean up if expired or used
		if preSign.used || now.After(preSign.ExpiresAt) {
			preSign.mu.Unlock()
			delete(pool.preSignatures, id)
			continue
		}

		preSign.mu.Unlock()
	}

	return nil, ErrInsufficientParties
}

// Size returns the current number of pre-signatures in the pool
func (pool *PreSignaturePool) Size() int {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return len(pool.preSignatures)
}

// Available returns the number of available (unused, non-expired) pre-signatures
func (pool *PreSignaturePool) Available() int {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	count := 0
	now := time.Now()

	for _, preSign := range pool.preSignatures {
		preSign.mu.Lock()
		if !preSign.used && now.Before(preSign.ExpiresAt) {
			count++
		}
		preSign.mu.Unlock()
	}

	return count
}

// evictOldest removes the oldest expired or used pre-signature
func (pool *PreSignaturePool) evictOldest() {
	var oldestID string
	var oldestTime time.Time
	first := true

	now := time.Now()

	for id, preSign := range pool.preSignatures {
		preSign.mu.Lock()

		// Prefer expired or used pre-signatures
		if preSign.used || now.After(preSign.ExpiresAt) {
			if first || preSign.CreatedAt.Before(oldestTime) {
				oldestID = id
				oldestTime = preSign.CreatedAt
				first = false
			}
		}

		preSign.mu.Unlock()
	}

	if oldestID != "" {
		delete(pool.preSignatures, oldestID)
	}
}

// Cleanup removes all expired and used pre-signatures
func (pool *PreSignaturePool) Cleanup() int {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	removed := 0
	now := time.Now()

	for id, preSign := range pool.preSignatures {
		preSign.mu.Lock()

		if preSign.used || now.After(preSign.ExpiresAt) {
			delete(pool.preSignatures, id)
			removed++
		}

		preSign.mu.Unlock()
	}

	return removed
}

// Clear removes all pre-signatures from the pool
func (pool *PreSignaturePool) Clear() {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// Securely zero all pre-signatures
	for _, preSign := range pool.preSignatures {
		preSign.mu.Lock()
		if preSign.k != nil {
			security.SecureZero(preSign.k.Bytes())
		}
		preSign.mu.Unlock()
	}

	pool.preSignatures = make(map[string]*PreSignature)
}
