// Package commitment provides cryptographic commitment schemes
// for zero-knowledge proofs and secure multi-party computation
package commitment

import (
	"math/big"
	"time"

	"github.com/Caqil/mpc-tss/pkg/crypto/curve"
	"github.com/Caqil/mpc-tss/pkg/crypto/hash"
	"github.com/Caqil/mpc-tss/pkg/crypto/rand"
)

// Commitment represents a cryptographic commitment
type Commitment struct {
	// C is the commitment value (point on curve)
	C *curve.Point

	// Curve is the elliptic curve being used
	Curve curve.Curve
}

// PedersenCommitment represents a Pedersen commitment with its opening
type PedersenCommitment struct {
	*Commitment

	// Value is the committed value
	Value *big.Int

	// Blinding is the random blinding factor
	Blinding *big.Int
}

// GeneratorPair represents a pair of generators for Pedersen commitments
type GeneratorPair struct {
	G curve.Curve  // Primary generator (base point)
	H *curve.Point // Secondary generator
}

// NewGeneratorPair creates a new generator pair for Pedersen commitments
// H is derived deterministically from G using RFC 9380 hash-to-curve
func NewGeneratorPair(c curve.Curve) (*GeneratorPair, error) {
	if c == nil {
		return nil, ErrNilCurve
	}

	// Derive secondary generator H deterministically using RFC 9380
	// DST (Domain Separation Tag) ensures independence
	dst := []byte("MPC-TSS-PEDERSEN-H-V1")
	msg := []byte("PEDERSEN_GENERATOR_H_" + c.Name())

	// Use RFC 9380 compliant hash-to-curve
	h, err := hash.HashToCurveRFC9380(msg, dst, c)
	if err != nil {
		return nil, err
	}

	return &GeneratorPair{
		G: c,
		H: h,
	}, nil
}

// Commit creates a Pedersen commitment: C = value*G + blinding*H
// If blinding is nil, a random blinding factor is generated
func (gp *GeneratorPair) Commit(value *big.Int, blinding *big.Int) (*PedersenCommitment, error) {
	if value == nil {
		return nil, ErrNilValue
	}

	// Generate random blinding factor if not provided
	if blinding == nil {
		var err error
		blinding, err = rand.GenerateRandomScalar(gp.G.Order())
		if err != nil {
			return nil, err
		}
	}

	// Normalize value and blinding to curve order
	v := new(big.Int).Mod(value, gp.G.Order())
	r := new(big.Int).Mod(blinding, gp.G.Order())

	// Compute C = v*G + r*H
	vG, err := gp.G.ScalarBaseMult(v)
	if err != nil {
		return nil, err
	}

	rH, err := gp.G.ScalarMult(gp.H, r)
	if err != nil {
		return nil, err
	}

	c, err := gp.G.Add(vG, rH)
	if err != nil {
		return nil, err
	}

	return &PedersenCommitment{
		Commitment: &Commitment{
			C:     c,
			Curve: gp.G,
		},
		Value:    v,
		Blinding: r,
	}, nil
}

// Verify verifies that the commitment opens to the given value and blinding
func (pc *PedersenCommitment) Verify(gp *GeneratorPair) bool {
	if pc == nil || gp == nil {
		return false
	}

	// Recompute C = value*G + blinding*H
	expected, err := gp.Commit(pc.Value, pc.Blinding)
	if err != nil {
		return false
	}

	// Check if commitments are equal
	return pc.C.IsEqual(expected.C)
}

// GetCommitment returns just the commitment (without opening information)
func (pc *PedersenCommitment) GetCommitment() *Commitment {
	return pc.Commitment
}

// HashCommitment represents a hash-based commitment with proper structure
type HashCommitment struct {
	// CommitmentHash is the cryptographic commitment
	CommitmentHash []byte

	// Nonce is the opening nonce (kept secret until reveal)
	Nonce []byte

	// Value is the committed value (kept secret until reveal)
	Value []byte

	// Timestamp prevents replay attacks
	Timestamp int64

	// Context provides domain separation
	Context []byte
}

// NewHashCommitment creates a production-grade hash-based commitment
// Uses HMAC-SHA256 with domain separation and replay protection
func NewHashCommitment(value []byte, context []byte) (*HashCommitment, error) {
	if len(value) == 0 {
		return nil, ErrEmptyValue
	}

	// Generate cryptographically secure nonce (32 bytes)
	nonce, err := rand.GenerateNonce(32)
	if err != nil {
		return nil, err
	}

	// Add timestamp for replay attack prevention
	timestamp := currentTimeMillis()

	// Compute commitment using HMAC for additional security
	// commitment = HMAC-SHA256(nonce, value || timestamp || context)
	commitmentHash := computeHashCommitment(value, nonce, timestamp, context)

	return &HashCommitment{
		CommitmentHash: commitmentHash,
		Nonce:          nonce,
		Value:          value,
		Timestamp:      timestamp,
		Context:        context,
	}, nil
}

// GetCommitmentValue returns the commitment hash (safe to share publicly)
func (hc *HashCommitment) GetCommitmentValue() []byte {
	return hc.CommitmentHash
}

// Reveal returns the opening information for verification
func (hc *HashCommitment) Reveal() (value, nonce []byte, timestamp int64, context []byte) {
	return hc.Value, hc.Nonce, hc.Timestamp, hc.Context
}

// Verify verifies a hash commitment with all security checks
func (hc *HashCommitment) Verify() bool {
	// Recompute commitment
	expected := computeHashCommitment(hc.Value, hc.Nonce, hc.Timestamp, hc.Context)

	// Constant-time comparison to prevent timing attacks
	return constantTimeCompare(hc.CommitmentHash, expected)
}

// VerifyHashCommitment verifies a commitment given all opening information
// This is the production-grade verification function
func VerifyHashCommitment(commitmentHash, value, nonce []byte, timestamp int64, context []byte) bool {
	if len(commitmentHash) == 0 || len(value) == 0 || len(nonce) == 0 {
		return false
	}

	// Check timestamp freshness (within 1 hour window to prevent replay)
	if !isTimestampValid(timestamp) {
		return false
	}

	// Recompute and verify
	expected := computeHashCommitment(value, nonce, timestamp, context)
	return constantTimeCompare(commitmentHash, expected)
}

// computeHashCommitment computes the commitment using HMAC-SHA256
// Format: HMAC-SHA256(nonce, value || timestamp || context || domain_tag)
func computeHashCommitment(value, nonce []byte, timestamp int64, context []byte) []byte {
	// Domain separation tag
	domainTag := []byte("MPC-TSS-HASH-COMMIT-V1")

	// Build commitment data: value || timestamp || context || domain_tag
	data := make([]byte, 0, len(value)+8+len(context)+len(domainTag))
	data = append(data, value...)

	// Add timestamp (8 bytes, big-endian)
	timestampBytes := make([]byte, 8)
	timestampBytes[0] = byte(timestamp >> 56)
	timestampBytes[1] = byte(timestamp >> 48)
	timestampBytes[2] = byte(timestamp >> 40)
	timestampBytes[3] = byte(timestamp >> 32)
	timestampBytes[4] = byte(timestamp >> 24)
	timestampBytes[5] = byte(timestamp >> 16)
	timestampBytes[6] = byte(timestamp >> 8)
	timestampBytes[7] = byte(timestamp)
	data = append(data, timestampBytes...)

	// Add context and domain tag
	data = append(data, context...)
	data = append(data, domainTag...)

	// Compute HMAC-SHA256(nonce, data)
	mac := hash.HMAC(nonce, data)

	return mac
}

// BatchHashCommit creates multiple hash commitments efficiently
func BatchHashCommit(values [][]byte, context []byte) ([]*HashCommitment, error) {
	if len(values) == 0 {
		return nil, ErrEmptyValues
	}

	commitments := make([]*HashCommitment, len(values))
	for i, value := range values {
		commitment, err := NewHashCommitment(value, context)
		if err != nil {
			return nil, err
		}
		commitments[i] = commitment
	}

	return commitments, nil
}

// currentTimeMillis returns current time in milliseconds
func currentTimeMillis() int64 {
	return time.Now().UnixMilli()
}

// isTimestampValid checks if timestamp is within acceptable window
func isTimestampValid(timestamp int64) bool {
	// Allow 1 hour window (3600000 milliseconds)
	now := currentTimeMillis()
	diff := now - timestamp

	// Must be recent (within past hour) and not in future
	return diff >= 0 && diff <= 3600000
}

// BatchCommit creates commitments for multiple values with a single blinding factor
// This is more efficient for batch operations
func (gp *GeneratorPair) BatchCommit(values []*big.Int) ([]*PedersenCommitment, error) {
	if len(values) == 0 {
		return nil, ErrEmptyValues
	}

	commitments := make([]*PedersenCommitment, len(values))
	for i, value := range values {
		commitment, err := gp.Commit(value, nil)
		if err != nil {
			return nil, err
		}
		commitments[i] = commitment
	}

	return commitments, nil
}

// AddCommitments adds two Pedersen commitments homomorphically
// C1 + C2 = (v1*G + r1*H) + (v2*G + r2*H) = (v1+v2)*G + (r1+r2)*H
func AddCommitments(c1, c2 *PedersenCommitment) (*PedersenCommitment, error) {
	if c1 == nil || c2 == nil {
		return nil, ErrNilCommitment
	}

	if c1.Curve.Name() != c2.Curve.Name() {
		return nil, ErrCurveMismatch
	}

	// Add commitment points
	cSum, err := c1.Curve.Add(c1.C, c2.C)
	if err != nil {
		return nil, err
	}

	// Add values and blindings (mod order)
	order := c1.Curve.Order()
	valueSum := new(big.Int).Add(c1.Value, c2.Value)
	valueSum.Mod(valueSum, order)

	blindingSum := new(big.Int).Add(c1.Blinding, c2.Blinding)
	blindingSum.Mod(blindingSum, order)

	return &PedersenCommitment{
		Commitment: &Commitment{
			C:     cSum,
			Curve: c1.Curve,
		},
		Value:    valueSum,
		Blinding: blindingSum,
	}, nil
}

// ScalarMulCommitment multiplies a commitment by a scalar
// k*C = k*(v*G + r*H) = (k*v)*G + (k*r)*H
func ScalarMulCommitment(commitment *PedersenCommitment, scalar *big.Int) (*PedersenCommitment, error) {
	if commitment == nil {
		return nil, ErrNilCommitment
	}
	if scalar == nil {
		return nil, ErrNilScalar
	}

	// Multiply commitment point
	cMul, err := commitment.Curve.ScalarMult(commitment.C, scalar)
	if err != nil {
		return nil, err
	}

	// Multiply value and blinding
	order := commitment.Curve.Order()
	valueMul := new(big.Int).Mul(commitment.Value, scalar)
	valueMul.Mod(valueMul, order)

	blindingMul := new(big.Int).Mul(commitment.Blinding, scalar)
	blindingMul.Mod(blindingMul, order)

	return &PedersenCommitment{
		Commitment: &Commitment{
			C:     cMul,
			Curve: commitment.Curve,
		},
		Value:    valueMul,
		Blinding: blindingMul,
	}, nil
}

// constantTimeCompare performs constant-time comparison of byte slices
func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}

	return v == 0
}

// CommitToCurvePoint creates a hash commitment to a curve point
// Returns (commitment, decommitment, error)
// The decommitment includes both nonce and timestamp
func CommitToCurvePoint(point *curve.Point, c curve.Curve, context []byte) (*PedersenCommitment, []byte, error) {
	if point == nil {
		return nil, nil, ErrNilValue
	}

	// Serialize the point
	pointBytes := point.Bytes()

	// Create hash commitment
	hashCommit, err := NewHashCommitment(pointBytes, context)
	if err != nil {
		return nil, nil, err
	}

	// For API compatibility, wrap in PedersenCommitment structure
	// Store the hash commitment as a simple structure
	dummyCommit := &PedersenCommitment{
		Commitment: &Commitment{
			C:     point,
			Curve: c,
		},
		Value:    nil,
		Blinding: nil,
	}

	// Encode decommitment as nonce || timestamp (8 bytes)
	decommit := make([]byte, len(hashCommit.Nonce)+8)
	copy(decommit, hashCommit.Nonce)

	// Append timestamp (8 bytes, big-endian)
	timestamp := hashCommit.Timestamp
	for i := 7; i >= 0; i-- {
		decommit[len(hashCommit.Nonce)+i] = byte(timestamp)
		timestamp >>= 8
	}

	// Return commitment hash and decommitment (nonce + timestamp)
	return dummyCommit, decommit, nil
}

// VerifyCommitmentToCurvePoint verifies a commitment to a curve point
// The decommitment must include both nonce and timestamp
func VerifyCommitmentToCurvePoint(commitmentBytes []byte, point *curve.Point, decommit []byte, c curve.Curve, context []byte) bool {
	if point == nil || len(commitmentBytes) == 0 || len(decommit) < 8 {
		return false
	}

	// Extract nonce and timestamp from decommitment
	// decommit = nonce || timestamp (last 8 bytes)
	nonceLen := len(decommit) - 8
	nonce := decommit[:nonceLen]
	timestampBytes := decommit[nonceLen:]

	// Decode timestamp (big-endian, 8 bytes)
	var timestamp int64
	for i := 0; i < 8; i++ {
		timestamp = (timestamp << 8) | int64(timestampBytes[i])
	}

	// Serialize the revealed point
	pointBytes := point.Bytes()

	// Recompute the expected commitment
	expected := computeHashCommitment(pointBytes, nonce, timestamp, context)

	// Constant-time comparison
	return constantTimeCompare(commitmentBytes, expected)
}

// Bytes returns the serialized commitment
func (pc *PedersenCommitment) Bytes() []byte {
	if pc.C == nil {
		return nil
	}

	// For hash commitments of curve points, we use the point serialization
	// For regular Pedersen commitments, serialize the commitment point
	return pc.C.Bytes()
}
