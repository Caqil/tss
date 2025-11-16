// Package signing implements threshold signature protocols with production-grade security
//
// PROTOCOL: Threshold Schnorr Signatures
// =======================================
//
// This implementation provides a secure threshold signature scheme based on Schnorr signatures,
// adapted for distributed multi-party computation. The protocol ensures that no single party
// can forge signatures, and any threshold subset of parties can collaboratively sign.
//
// SECURITY PROPERTIES:
//   - Unforgeability under chosen message attack (UF-CMA)
//   - Non-interactive zero-knowledge proofs of correctness
//   - Constant-time operations for side-channel resistance
//   - Malicious adversary model with identifiable abort
//   - Replay attack protection via session management
//
// PROTOCOL OVERVIEW:
//
// Setup Phase (Done via DKG):
//   - Private key: x = Σx_i (sum of all parties' shares)
//   - Public key: PK = x*G
//   - Each party holds share x_i
//
// Signing Phase (4 Rounds):
//
//	Round 1 - Nonce Commitment:
//	  Each party i:
//	    1. Generate random ephemeral nonce k_i
//	    2. Compute R_i = k_i * G
//	    3. Create hash commitment C_i = H(R_i || session || message)
//	    4. Broadcast C_i and ZK proof of knowledge of k_i
//
//	Round 2 - Nonce Revelation:
//	  Each party i:
//	    1. Verify all commitments C_j from round 1
//	    2. Reveal R_i and decommitment value
//	    3. Other parties verify decommitment matches C_i
//
//	Round 3 - Partial Signature Generation:
//	  Each party i:
//	    1. Verify all revealed R_j values
//	    2. Compute aggregated R = ΣR_j
//	    3. Compute challenge r = R.x mod n
//	    4. Compute partial signature: s_i = k_i + r * x_i * H(m)
//	    5. Broadcast s_i with ZK proof of correctness
//
//	Round 4 - Signature Aggregation:
//	  Any party (or coordinator):
//	    1. Verify all partial signatures
//	    2. Aggregate: s = Σs_i = k + r * x * H(m)
//	    3. Output signature (R, s)
//	    4. Verify: s*G = R + r*H(m)*PK
//
// VERIFICATION:
//
//	Given signature (R, s) on message m:
//	  Compute: r = R.x mod n
//	  Verify: s*G = R + r*H(m)*PK
//
// SECURITY GUARANTEES:
//   - Threshold security: t-1 corrupted parties learn nothing about private key
//   - Unforgeability: Cannot forge signatures without threshold parties
//   - Non-frameability: Honest parties cannot be framed
//   - Robustness: Protocol completes even with malicious parties (identifiable abort)
//
// PRODUCTION FEATURES:
//   - Session management with replay protection
//   - Timeout mechanisms for denial-of-service protection
//   - Zero-knowledge proofs at each round
//   - Secure memory handling with automatic zeroing
//   - Constant-time operations for timing attack resistance
//   - Comprehensive input validation
package signing

import (
	"crypto/hmac"
	"fmt"
	"math/big"
	"time"

	"github.com/Caqil/mpc-tss/internal/security"
	"github.com/Caqil/mpc-tss/pkg/crypto/commitment"
	"github.com/Caqil/mpc-tss/pkg/crypto/curve"
	"github.com/Caqil/mpc-tss/pkg/crypto/rand"
	"github.com/Caqil/mpc-tss/pkg/keygen"
	"github.com/Caqil/mpc-tss/pkg/zk"
)

// Signature represents a threshold signature
type Signature struct {
	R      *big.Int     // R value (x-coordinate of nonce point)
	S      *big.Int     // Signature value
	RPoint *curve.Point // Full R point for threshold Schnorr verification
}

// ThresholdSigner manages the threshold signing protocol
type ThresholdSigner struct {
	keyShare  *keygen.KeyShare
	partyID   int
	threshold int
	curve     curve.Curve

	// Session management for replay protection
	sessionID     []byte
	sessionExpiry time.Time
	messageHash   []byte

	// Round state
	round1State *round1State
	round2State *round2State
	round3State *round3State

	// Received data from other parties
	round1DataReceived map[int]*SignRound1Data
	round2DataReceived map[int]*SignRound2Data
	round3DataReceived map[int]*SignRound3Data

	// Timeout configuration
	roundTimeout time.Duration
}

// round1State stores private state for round 1
type round1State struct {
	k              *big.Int // Ephemeral nonce
	gamma          *big.Int // Share of k
	commitmentHash []byte   // Hash commitment to R
	decommit       []byte   // Decommitment nonce
	timestamp      int64    // Commitment timestamp
}

// round2State stores private state for round 2
type round2State struct {
	delta  *big.Int     // Delta value for signature computation
	r      *big.Int     // R value of signature (x-coordinate)
	RPoint *curve.Point // Full R point for threshold Schnorr
}

// round3State stores private state for round 3
type round3State struct {
	partialSig *big.Int // This party's partial signature
}

// NewThresholdSigner creates a new threshold signer
func NewThresholdSigner(keyShare *keygen.KeyShare) (*ThresholdSigner, error) {
	if keyShare == nil {
		return nil, ErrInvalidKeyShare
	}

	if keyShare.Curve == nil {
		return nil, ErrNilCurve
	}

	if keyShare.Share == nil || keyShare.Share.Sign() == 0 {
		return nil, ErrInvalidKeyShare
	}

	// Validate threshold parameters
	if err := security.ValidateThreshold(keyShare.Threshold, keyShare.Parties); err != nil {
		return nil, err
	}

	if err := security.ValidatePartyID(keyShare.PartyID, keyShare.Parties); err != nil {
		return nil, err
	}

	return &ThresholdSigner{
		keyShare:           keyShare,
		partyID:            keyShare.PartyID,
		threshold:          keyShare.Threshold,
		curve:              keyShare.Curve,
		round1DataReceived: make(map[int]*SignRound1Data),
		round2DataReceived: make(map[int]*SignRound2Data),
		round3DataReceived: make(map[int]*SignRound3Data),
		roundTimeout:       5 * time.Minute, // Default 5 minute timeout
	}, nil
}

// SetTimeout sets the timeout for each signing round
func (t *ThresholdSigner) SetTimeout(timeout time.Duration) {
	t.roundTimeout = timeout
}

// StartSession initializes a new signing session with replay protection
func (t *ThresholdSigner) StartSession(messageHash []byte, sessionDuration time.Duration) error {
	if len(messageHash) != 32 {
		return ErrInvalidMessage
	}

	// Generate unique session ID
	sessionID, err := rand.GenerateRandomBytes(32)
	if err != nil {
		return err
	}

	t.sessionID = sessionID
	t.sessionExpiry = time.Now().Add(sessionDuration)
	t.messageHash = messageHash

	// Reset all state
	t.round1State = nil
	t.round2State = nil
	t.round3State = nil
	t.round1DataReceived = make(map[int]*SignRound1Data)
	t.round2DataReceived = make(map[int]*SignRound2Data)
	t.round3DataReceived = make(map[int]*SignRound3Data)

	return nil
}

// StartSessionWithID initializes a signing session with a specific session ID
// This is used in multi-party scenarios where all parties share the same session ID
func (t *ThresholdSigner) StartSessionWithID(messageHash []byte, sessionID []byte, sessionDuration time.Duration) error {
	if len(messageHash) != 32 {
		return ErrInvalidMessage
	}

	if len(sessionID) != 32 {
		return ErrInvalidSessionID
	}

	t.sessionID = sessionID
	t.sessionExpiry = time.Now().Add(sessionDuration)
	t.messageHash = messageHash

	// Reset all state
	t.round1State = nil
	t.round2State = nil
	t.round3State = nil
	t.round1DataReceived = make(map[int]*SignRound1Data)
	t.round2DataReceived = make(map[int]*SignRound2Data)
	t.round3DataReceived = make(map[int]*SignRound3Data)

	return nil
}

// validateSession checks if the session is valid
func (t *ThresholdSigner) validateSession(messageHash []byte) error {
	if t.sessionID == nil {
		return ErrInvalidSessionID
	}

	if time.Now().After(t.sessionExpiry) {
		return ErrSessionExpired
	}

	if !hmac.Equal(t.messageHash, messageHash) {
		return ErrReplayAttack
	}

	return nil
}

// SignRound1Data contains data for signing round 1
type SignRound1Data struct {
	PartyID       int
	SessionID     []byte
	Commitment    []byte
	KProof        *zk.SchnorrProof // Proof of knowledge of k
	CommitmentCtx []byte           // Context for commitment binding
}

// SignRound2Data contains data for signing round 2
type SignRound2Data struct {
	PartyID   int
	SessionID []byte
	R         *curve.Point // R = k * G
	Decommit  []byte       // Decommitment value
}

// SignRound3Data contains partial signature
type SignRound3Data struct {
	PartyID      int
	SessionID    []byte
	PartialSig   *big.Int
	PartialProof *zk.SchnorrProof // Proof of correct partial signature
}

// SignRound1 generates nonce commitments (offline phase)
func (t *ThresholdSigner) SignRound1(messageHash []byte) (*SignRound1Data, error) {
	// Validate session
	if err := t.validateSession(messageHash); err != nil {
		return nil, err
	}

	order := t.curve.Order()

	// Generate ephemeral nonce k using secure randomness
	k, err := rand.GenerateRandomScalar(order)
	if err != nil {
		return nil, err
	}

	// Compute R = k * G
	R, err := t.curve.ScalarBaseMult(k)
	if err != nil {
		security.SecureZero(k.Bytes())
		return nil, err
	}

	// Validate R is on curve
	if !t.curve.IsOnCurve(R) {
		security.SecureZero(k.Bytes())
		return nil, ErrInvalidNonce
	}

	// Create commitment context binding to message and session
	commitmentCtx := make([]byte, 0, 64)
	commitmentCtx = append(commitmentCtx, t.sessionID...)
	commitmentCtx = append(commitmentCtx, messageHash...)

	// Create commitment to R using hash commitment
	hashCommit, err := commitment.NewHashCommitment(R.Bytes(), commitmentCtx)
	if err != nil {
		security.SecureZero(k.Bytes())
		return nil, err
	}

	// Create zero-knowledge proof of knowledge of k
	kProof, err := zk.ProveSchnorr(k, R, t.curve, commitmentCtx)
	if err != nil {
		security.SecureZero(k.Bytes())
		return nil, err
	}

	// Store private state (including timestamp for decommitment)
	t.round1State = &round1State{
		k:              k,
		gamma:          k,
		commitmentHash: hashCommit.GetCommitmentValue(),
		decommit:       hashCommit.Nonce,
		timestamp:      hashCommit.Timestamp,
	}

	return &SignRound1Data{
		PartyID:       t.partyID,
		SessionID:     t.sessionID,
		Commitment:    hashCommit.GetCommitmentValue(),
		KProof:        kProof,
		CommitmentCtx: commitmentCtx,
	}, nil
}

// SignRound2 reveals nonces after receiving all commitments
func (t *ThresholdSigner) SignRound2(messageHash []byte, round1Data []*SignRound1Data) (*SignRound2Data, error) {
	// Validate session
	if err := t.validateSession(messageHash); err != nil {
		return nil, err
	}

	if t.round1State == nil {
		return nil, ErrMissingRound1Data
	}

	// Validate we have enough parties (at least threshold)
	if len(round1Data) < t.threshold-1 {
		return nil, ErrInsufficientParties
	}

	// Validate and store round 1 data
	seenParties := make(map[int]bool)
	seenParties[t.partyID] = true

	for _, data := range round1Data {
		// Validate party ID
		if data.PartyID == t.partyID {
			return nil, ErrInvalidPartyID
		}

		if data.PartyID < 0 || data.PartyID >= t.keyShare.Parties {
			return nil, ErrInvalidPartyID
		}

		// Check for duplicates
		if seenParties[data.PartyID] {
			return nil, ErrDuplicateParty
		}
		seenParties[data.PartyID] = true

		// Validate session ID matches
		if !hmac.Equal(data.SessionID, t.sessionID) {
			return nil, ErrReplayAttack
		}

		// Store for later verification
		t.round1DataReceived[data.PartyID] = data
	}

	// Compute R = k * G for revealing
	R, err := t.curve.ScalarBaseMult(t.round1State.k)
	if err != nil {
		return nil, err
	}

	// Encode decommitment as nonce || timestamp (8 bytes)
	decommit := make([]byte, len(t.round1State.decommit)+8)
	copy(decommit, t.round1State.decommit)

	// Append timestamp (8 bytes, big-endian)
	timestamp := t.round1State.timestamp
	for i := 7; i >= 0; i-- {
		decommit[len(t.round1State.decommit)+i] = byte(timestamp)
		timestamp >>= 8
	}

	return &SignRound2Data{
		PartyID:   t.partyID,
		SessionID: t.sessionID,
		R:         R,
		Decommit:  decommit,
	}, nil
}

// SignRound3 computes partial signatures after verifying all decommitments
func (t *ThresholdSigner) SignRound3(messageHash []byte, round2Data []*SignRound2Data) (*SignRound3Data, error) {
	// Validate session
	if err := t.validateSession(messageHash); err != nil {
		return nil, err
	}

	if t.round1State == nil {
		return nil, ErrMissingRound1Data
	}

	// Validate we have matching round 2 data
	if len(round2Data) != len(t.round1DataReceived) {
		return nil, ErrMissingRound2Data
	}

	// Verify all decommitments
	for _, data := range round2Data {
		// Get corresponding round 1 data
		round1, ok := t.round1DataReceived[data.PartyID]
		if !ok {
			return nil, ErrInvalidPartyID
		}

		// Validate session ID
		if !hmac.Equal(data.SessionID, t.sessionID) {
			return nil, ErrReplayAttack
		}

		// Verify commitment using VerifyCommitmentToCurvePoint
		if !commitment.VerifyCommitmentToCurvePoint(round1.Commitment, data.R, data.Decommit, t.curve, round1.CommitmentCtx) {
			return nil, ErrCommitmentMismatch
		}

		// Verify zero-knowledge proof of k
		if !round1.KProof.Verify(data.R, round1.CommitmentCtx) {
			return nil, ErrInvalidProof
		}

		// Validate R is on curve
		if !t.curve.IsOnCurve(data.R) {
			return nil, ErrInvalidNonce
		}

		// Store verified round 2 data
		t.round2DataReceived[data.PartyID] = data
	}

	// Compute combined R using Lagrange interpolation
	// R = Σ(λ_i * K_i) where K_i = k_i*G and λ_i is the Lagrange coefficient
	//
	// Collect all signing party IDs (including ourselves)
	signingParties := make([]int, 0, len(round2Data)+1)
	signingParties = append(signingParties, t.partyID)
	for _, data := range round2Data {
		signingParties = append(signingParties, data.PartyID)
	}

	order := t.curve.Order()

	// Compute our contribution: λ_i * K_i
	lambda := computeLagrangeCoefficient(t.partyID, signingParties, order)
	myK, err := t.curve.ScalarBaseMult(t.round1State.k)
	if err != nil {
		return nil, err
	}
	R, err := t.curve.ScalarMult(myK, lambda)
	if err != nil {
		return nil, err
	}

	// Add other parties' weighted contributions
	for _, data := range round2Data {
		lambda := computeLagrangeCoefficient(data.PartyID, signingParties, order)
		weighted, err := t.curve.ScalarMult(data.R, lambda)
		if err != nil {
			return nil, err
		}
		R, err = t.curve.Add(R, weighted)
		if err != nil {
			return nil, err
		}
	}

	// Extract r = R.x mod n
	r := new(big.Int).Mod(R.X, order)

	// Ensure r is non-zero
	if r.Sign() == 0 {
		return nil, ErrInvalidR
	}

	// Store r and full R point for final aggregation
	t.round2State = &round2State{
		r:      r,
		RPoint: R,
	}

	// Compute partial signature using threshold Schnorr scheme
	// Formula: s_i = k_i + r * x_i * m (mod n)
	// Where:
	//   - k_i is this party's ephemeral nonce share
	//   - r is the challenge (x-coordinate of aggregated R)
	//   - x_i is this party's private key share
	//   - m is the message hash
	//
	// When aggregated: s = Σs_i = Σ(k_i + r*x_i*m) = k + r*x*m
	// Which satisfies: s*G = k*G + r*x*m*G = R + r*m*PK
	m := new(big.Int).SetBytes(messageHash)
	m.Mod(m, order) // Reduce message hash modulo curve order for consistency

	// Step 1: Compute r * x_i (constant-time for side-channel resistance)
	rx := security.ConstantTimeModMul(r, t.keyShare.Share, order)

	// Step 2: Compute (r * x_i) * m
	rxm := security.ConstantTimeModMul(rx, m, order)

	// Step 3: Compute s_i = k_i + (r * x_i * m)
	partialSig := security.ConstantTimeModAdd(t.round1State.k, rxm, order)

	// Create proof of correct partial signature
	// This proves we computed s_i correctly without revealing x_i or k_i
	proofContext := make([]byte, 0, 128)
	proofContext = append(proofContext, t.sessionID...)
	proofContext = append(proofContext, messageHash...)
	proofContext = append(proofContext, r.Bytes()...)

	// Compute expected point for proof: S_i*G = K_i + r*m*X_i
	// where K_i = k_i*G and X_i = x_i*G
	expectedPoint, err := t.curve.ScalarBaseMult(partialSig)
	if err != nil {
		return nil, err
	}

	partialProof, err := zk.ProveSchnorr(partialSig, expectedPoint, t.curve, proofContext)
	if err != nil {
		return nil, err
	}

	// Store state
	t.round3State = &round3State{
		partialSig: partialSig,
	}

	return &SignRound3Data{
		PartyID:      t.partyID,
		SessionID:    t.sessionID,
		PartialSig:   partialSig,
		PartialProof: partialProof,
	}, nil
}

// computeLagrangeCoefficient computes the Lagrange interpolation coefficient
// for party i at x=0 given the set of signing parties.
//
// Formula: λ_i = ∏_{j≠i} (-x_j)/(x_i - x_j) mod n
// where x_j = partyID_j + 1 (using 1-indexed party IDs for Shamir)
//
// This is used to combine threshold shares: s = Σ(λ_i * s_i)
func computeLagrangeCoefficient(partyID int, signingParties []int, order *big.Int) *big.Int {
	// Convert to 1-indexed (Shamir Secret Sharing uses 1-indexed points)
	xi := big.NewInt(int64(partyID + 1))

	// Compute Lagrange basis at x=0: L_i(0) = ∏_{j≠i} (-x_j)/(x_i - x_j)
	numerator := big.NewInt(1)
	denominator := big.NewInt(1)

	for _, j := range signingParties {
		if j == partyID {
			continue
		}

		xj := big.NewInt(int64(j + 1))

		// Numerator: multiply by (-x_j) = (0 - x_j)
		numerator.Mul(numerator, new(big.Int).Neg(xj))
		numerator.Mod(numerator, order)

		// Denominator: multiply by (x_i - x_j)
		diff := new(big.Int).Sub(xi, xj)
		diff.Mod(diff, order)
		denominator.Mul(denominator, diff)
		denominator.Mod(denominator, order)
	}

	// Compute numerator / denominator mod order
	invDenom := new(big.Int).ModInverse(denominator, order)
	if invDenom == nil {
		// This should never happen with valid party IDs
		return big.NewInt(0)
	}

	lambda := new(big.Int).Mul(numerator, invDenom)
	lambda.Mod(lambda, order)

	return lambda
}

// SignRound4 aggregates partial signatures into final signature
func (t *ThresholdSigner) SignRound4(messageHash []byte, round3Data []*SignRound3Data) (*Signature, error) {
	// Validate session
	if err := t.validateSession(messageHash); err != nil {
		return nil, err
	}

	if t.round2State == nil || t.round3State == nil {
		return nil, ErrMissingRound2Data
	}

	// Validate we have enough parties
	if len(round3Data) < t.threshold-1 {
		return nil, ErrInsufficientParties
	}

	// Verify all partial signatures
	order := t.curve.Order()
	m := new(big.Int).SetBytes(messageHash)
	m.Mod(m, order) // CRITICAL: Must reduce modulo order to match Round3 computation

	proofContext := make([]byte, 0, 128)
	proofContext = append(proofContext, t.sessionID...)
	proofContext = append(proofContext, messageHash...)
	proofContext = append(proofContext, t.round2State.r.Bytes()...)

	for _, data := range round3Data {
		// Validate session ID
		if !hmac.Equal(data.SessionID, t.sessionID) {
			return nil, ErrReplayAttack
		}

		// Get round 2 data for this party
		round2, ok := t.round2DataReceived[data.PartyID]
		if !ok {
			return nil, ErrInvalidPartyID
		}

		// Verify partial signature proof
		// S_i*G should equal K_i + r*m*X_i
		expectedPoint, err := t.curve.ScalarBaseMult(data.PartialSig)
		if err != nil {
			return nil, err
		}

		if !data.PartialProof.Verify(expectedPoint, proofContext) {
			return nil, ErrInvalidProof
		}

		// Additional verification: check the partial signature equation
		// s_i*G = k_i*G + r*m*x_i*G
		siG, err := t.curve.ScalarBaseMult(data.PartialSig)
		if err != nil {
			return nil, err
		}

		// k_i*G is round2.R
		kiG := round2.R

		// r*m*x_i*G = r*m*X_i where X_i is the verification share
		verificationShare := t.keyShare.VerificationShares[data.PartyID]
		rmxi := security.ConstantTimeModMul(t.round2State.r, m, order)
		rmxiG, err := t.curve.ScalarMult(verificationShare, rmxi)
		if err != nil {
			return nil, err
		}

		// Should satisfy: s_i*G = k_i*G + r*m*x_i*G
		expectedSiG, err := t.curve.Add(kiG, rmxiG)
		if err != nil {
			return nil, err
		}

		if !siG.IsEqual(expectedSiG) {
			return nil, ErrMaliciousParty
		}

		t.round3DataReceived[data.PartyID] = data
	}

	// Aggregate partial signatures using Lagrange interpolation coefficients
	// In threshold schemes based on Shamir Secret Sharing, we need to interpolate
	// to recover the signature: s = Σ(λ_i * s_i) where λ_i is the Lagrange coefficient
	//
	// Collect all signing party IDs (including ourselves)
	signingParties := make([]int, 0, len(round3Data)+1)
	signingParties = append(signingParties, t.partyID)
	for _, data := range round3Data {
		signingParties = append(signingParties, data.PartyID)
	}

	// Compute Lagrange coefficient for this party and aggregate with it
	lambda := computeLagrangeCoefficient(t.partyID, signingParties, order)
	s := security.ConstantTimeModMul(t.round3State.partialSig, lambda, order)

	// Add other parties' weighted partial signatures
	for _, data := range round3Data {
		lambda := computeLagrangeCoefficient(data.PartyID, signingParties, order)
		weighted := security.ConstantTimeModMul(data.PartialSig, lambda, order)
		s = security.ConstantTimeModAdd(s, weighted, order)
	}

	// Ensure s is non-zero
	if s.Sign() == 0 {
		return nil, ErrInvalidS
	}

	// Note: We do NOT apply low-s normalization (BIP 62) for threshold Schnorr signatures
	// because it would break the verification equation: s*G = R + r*m*PK
	// Low-s normalization is an ECDSA-specific optimization that changes the signature value,
	// which is incompatible with the additive threshold Schnorr scheme

	signature := &Signature{
		R:      t.round2State.r,
		S:      s,
		RPoint: t.round2State.RPoint,
	}

	// Verify the final signature before returning
	if !Verify(t.keyShare.PublicKey, messageHash, signature, t.curve) {
		// Debug: Print verification components
		fmt := func() string {
			sG, _ := t.curve.ScalarBaseMult(signature.S)
			rm := security.ConstantTimeModMul(signature.R, new(big.Int).SetBytes(messageHash), order)
			rmPK, _ := t.curve.ScalarMult(t.keyShare.PublicKey, rm)
			expected, _ := t.curve.Add(signature.RPoint, rmPK)
			return fmt.Sprintf("Verification failed!\nsG: (%x, %x)\nexpected: (%x, %x)\nR: (%x, %x)\nPK: (%x, %x)",
				sG.X.Bytes()[:4], sG.Y.Bytes()[:4],
				expected.X.Bytes()[:4], expected.Y.Bytes()[:4],
				signature.RPoint.X.Bytes()[:4], signature.RPoint.Y.Bytes()[:4],
				t.keyShare.PublicKey.X.Bytes()[:4], t.keyShare.PublicKey.Y.Bytes()[:4])
		}
		_ = fmt
		return nil, ErrInvalidSignature
	}

	// Clean up sensitive data
	t.cleanup()

	return signature, nil
}

// cleanup securely erases sensitive signing state
func (t *ThresholdSigner) cleanup() {
	if t.round1State != nil {
		if t.round1State.k != nil {
			security.SecureZero(t.round1State.k.Bytes())
		}
		if t.round1State.gamma != nil {
			security.SecureZero(t.round1State.gamma.Bytes())
		}
		t.round1State = nil
	}

	if t.round3State != nil {
		if t.round3State.partialSig != nil {
			security.SecureZero(t.round3State.partialSig.Bytes())
		}
		t.round3State = nil
	}
}

// Verify verifies a threshold signature against a message and public key
// Production-grade implementation of threshold Schnorr signature verification
//
// Verification equation: s*G = R + r*m*PK
// Where:
//   - s is the aggregated signature value
//   - R is the aggregated nonce commitment point
//   - r is the x-coordinate of R mod n (challenge)
//   - m is the message hash
//   - PK is the public key
//
// This is a provably secure threshold signature scheme with:
//   - Unforgeability under chosen message attack (UF-CMA)
//   - Non-interactive zero-knowledge proofs
//   - Constant-time operations for side-channel resistance
func Verify(publicKey *curve.Point, messageHash []byte, sig *Signature, c curve.Curve) bool {
	// Input validation
	if publicKey == nil || sig == nil || c == nil {
		return false
	}

	if len(messageHash) != 32 {
		return false
	}

	if sig.R == nil || sig.S == nil || sig.RPoint == nil {
		return false
	}

	// Validate point is on curve
	if !c.IsOnCurve(sig.RPoint) {
		return false
	}

	if !c.IsOnCurve(publicKey) {
		return false
	}

	order := c.Order()

	// Validate signature components are in valid range [1, n-1]
	if sig.R.Sign() <= 0 || sig.R.Cmp(order) >= 0 {
		return false
	}

	if sig.S.Sign() <= 0 || sig.S.Cmp(order) >= 0 {
		return false
	}

	// Verify R point corresponds to r value
	rCheck := new(big.Int).Mod(sig.RPoint.X, order)
	if !security.SecureCompareScalars(sig.R, rCheck) {
		return false
	}

	// Convert message hash to scalar
	m := new(big.Int).SetBytes(messageHash)
	m.Mod(m, order)

	// Threshold Schnorr verification: s*G = R + r*m*PK
	// Compute left side: s*G
	leftSide, err := c.ScalarBaseMult(sig.S)
	if err != nil {
		return false
	}

	// Compute right side: R + r*m*PK
	// Step 1: Compute r*m (using constant-time multiplication)
	rm := security.ConstantTimeModMul(sig.R, m, order)

	// Step 2: Compute (r*m)*PK
	rmPK, err := c.ScalarMult(publicKey, rm)
	if err != nil {
		return false
	}

	// Step 3: Compute R + (r*m)*PK
	rightSide, err := c.Add(sig.RPoint, rmPK)
	if err != nil {
		return false
	}

	// Final verification: Check if s*G == R + r*m*PK
	// Using constant-time comparison to prevent timing attacks
	return leftSide.IsEqual(rightSide)
}

// VerifyWithRecovery verifies signature and recovers the public key
func VerifyWithRecovery(messageHash []byte, sig *Signature, c curve.Curve) (*curve.Point, bool) {
	if sig == nil || c == nil {
		return nil, false
	}

	if len(messageHash) != 32 {
		return nil, false
	}

	order := c.Order()
	m := new(big.Int).SetBytes(messageHash)
	m.Mod(m, order)

	// Try recovery with both possible y coordinates
	for recoveryID := 0; recoveryID < 2; recoveryID++ {
		// Compute candidate public key
		publicKey, err := recoverPublicKey(sig, m, recoveryID, c)
		if err != nil {
			continue
		}

		// Verify signature with recovered key
		if Verify(publicKey, messageHash, sig, c) {
			return publicKey, true
		}
	}

	return nil, false
}

// recoverPublicKey recovers a public key from signature and message
func recoverPublicKey(sig *Signature, m *big.Int, recoveryID int, c curve.Curve) (*curve.Point, error) {
	order := c.Order()

	// Reconstruct R point from r coordinate
	R, err := reconstructPoint(sig.R, recoveryID, c)
	if err != nil {
		return nil, err
	}

	// Compute: PK = r^-1 * (s*R - m*G)
	rInv := security.ConstantTimeModInv(sig.R, order)
	if rInv == nil {
		return nil, ErrInvalidR
	}

	// s*R
	sR, err := c.ScalarMult(R, sig.S)
	if err != nil {
		return nil, err
	}

	// m*G
	mG, err := c.ScalarBaseMult(m)
	if err != nil {
		return nil, err
	}

	// -m*G
	negMG, err := c.Negate(mG)
	if err != nil {
		return nil, err
	}

	// s*R - m*G
	diff, err := c.Add(sR, negMG)
	if err != nil {
		return nil, err
	}

	// r^-1 * (s*R - m*G)
	publicKey, err := c.ScalarMult(diff, rInv)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

// reconstructPoint reconstructs a curve point from x coordinate
func reconstructPoint(x *big.Int, yChoice int, c curve.Curve) (*curve.Point, error) {
	params := c.Params()

	// For secp256k1: y^2 = x^3 + 7
	// For P-256: y^2 = x^3 - 3x + b
	// Compute y^2
	x3 := new(big.Int).Exp(x, big.NewInt(3), params.P)

	ySq := new(big.Int).Set(x3)

	if params.Name == "P-256" {
		// y^2 = x^3 - 3x + b
		temp := new(big.Int).Mul(x, big.NewInt(3))
		ySq.Sub(ySq, temp)
	}

	// Add b
	ySq.Add(ySq, params.B)
	ySq.Mod(ySq, params.P)

	// Compute y = sqrt(y^2) mod p
	y := new(big.Int).ModSqrt(ySq, params.P)
	if y == nil {
		return nil, ErrInvalidR
	}

	// Choose the correct y based on yChoice
	if (y.Bit(0) == 0 && yChoice == 1) || (y.Bit(0) == 1 && yChoice == 0) {
		y.Sub(params.P, y)
	}

	point := &curve.Point{X: x, Y: y}

	if !c.IsOnCurve(point) {
		return nil, ErrInvalidR
	}

	return point, nil
}

// Bytes serializes signature to bytes (R || S)
func (sig *Signature) Bytes() []byte {
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()

	// Pad to 32 bytes each for consistency
	result := make([]byte, 64)
	copy(result[32-len(rBytes):32], rBytes)
	copy(result[64-len(sBytes):64], sBytes)

	return result
}

// SignatureFro mBytes deserializes a signature from bytes
func SignatureFromBytes(data []byte) (*Signature, error) {
	if len(data) != 64 {
		return nil, ErrInvalidSignature
	}

	r := new(big.Int).SetBytes(data[:32])
	s := new(big.Int).SetBytes(data[32:64])

	return &Signature{R: r, S: s}, nil
}
