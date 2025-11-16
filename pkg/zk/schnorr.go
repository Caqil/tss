// Package zk implements zero-knowledge proof systems for MPC-TSS
package zk

import (
	"math/big"

	"github.com/Caqil/mpc-tss/internal/security"
	"github.com/Caqil/mpc-tss/pkg/crypto/curve"
	"github.com/Caqil/mpc-tss/pkg/crypto/hash"
	"github.com/Caqil/mpc-tss/pkg/crypto/rand"
)

// SchnorrProof represents a Schnorr proof of knowledge of discrete logarithm
// Proves knowledge of x such that Y = x*G without revealing x
type SchnorrProof struct {
	// Commitment is the prover's commitment R = k*G
	Commitment *curve.Point

	// Challenge is the Fiat-Shamir challenge e = H(G, Y, R, context)
	Challenge *big.Int

	// Response is z = k + e*x mod n
	Response *big.Int

	// Curve is the elliptic curve being used
	Curve curve.Curve
}

// ProveSchnorr creates a Schnorr proof of knowledge of discrete log
// Proves knowledge of secret such that publicPoint = secret * G
// Uses Fiat-Shamir heuristic for non-interactive proof
func ProveSchnorr(secret *big.Int, publicPoint *curve.Point, c curve.Curve, context []byte) (*SchnorrProof, error) {
	if secret == nil {
		return nil, ErrNilSecret
	}
	if publicPoint == nil {
		return nil, ErrNilPublicPoint
	}
	if c == nil {
		return nil, ErrNilCurve
	}

	// Validate that publicPoint = secret * G
	expectedPoint, err := c.ScalarBaseMult(secret)
	if err != nil {
		return nil, err
	}
	if !expectedPoint.IsEqual(publicPoint) {
		return nil, ErrInvalidWitness
	}

	// Step 1: Generate random nonce k ∈ [1, n-1]
	order := c.Order()
	k, err := rand.GenerateRandomScalar(order)
	if err != nil {
		return nil, err
	}

	// Step 2: Compute commitment R = k*G
	commitment, err := c.ScalarBaseMult(k)
	if err != nil {
		return nil, err
	}

	// Step 3: Compute Fiat-Shamir challenge
	// e = H(G || Y || R || context)
	challenge := computeSchnorrChallenge(c, publicPoint, commitment, context)

	// Step 4: Compute response z = k + e*x mod n
	// z = k + e*secret
	ex := new(big.Int).Mul(challenge, secret)
	response := new(big.Int).Add(k, ex)
	response.Mod(response, order)

	// Securely zero the nonce
	security.SecureZero(k.Bytes())

	return &SchnorrProof{
		Commitment: commitment,
		Challenge:  challenge,
		Response:   response,
		Curve:      c,
	}, nil
}

// VerifySchnorr verifies a Schnorr proof
// Checks that z*G = R + e*Y
func (sp *SchnorrProof) Verify(publicPoint *curve.Point, context []byte) bool {
	if sp == nil || publicPoint == nil {
		return false
	}

	// Recompute challenge
	expectedChallenge := computeSchnorrChallenge(sp.Curve, publicPoint, sp.Commitment, context)

	// Verify challenge matches (prevents proof malleability)
	if !security.SecureCompareScalars(sp.Challenge, expectedChallenge) {
		return false
	}

	// Verify: z*G = R + e*Y
	// Left side: z*G
	zG, err := sp.Curve.ScalarBaseMult(sp.Response)
	if err != nil {
		return false
	}

	// Right side: R + e*Y
	eY, err := sp.Curve.ScalarMult(publicPoint, sp.Challenge)
	if err != nil {
		return false
	}

	rightSide, err := sp.Curve.Add(sp.Commitment, eY)
	if err != nil {
		return false
	}

	// Constant-time comparison
	return zG.IsEqual(rightSide)
}

// computeSchnorrChallenge computes Fiat-Shamir challenge
// e = H(G || Y || R || context) mod n
func computeSchnorrChallenge(c curve.Curve, publicPoint, commitment *curve.Point, context []byte) *big.Int {
	// Build transcript: generator || publicPoint || commitment || context
	generator := c.Generator()

	transcript := make([]byte, 0, 256)
	transcript = append(transcript, generator.Bytes()...)
	transcript = append(transcript, publicPoint.Bytes()...)
	transcript = append(transcript, commitment.Bytes()...)
	transcript = append(transcript, context...)

	// Hash to challenge
	challenge := hash.FiatShamirChallenge(transcript, c.Order())

	return challenge
}

// SchnorrBatchProof represents a batch Schnorr proof for multiple secrets
type SchnorrBatchProof struct {
	// Proofs is the list of individual proofs
	Proofs []*SchnorrProof

	// AggregateChallenge is the combined challenge (optional optimization)
	AggregateChallenge *big.Int
}

// ProveBatchSchnorr creates proofs for multiple discrete logs efficiently
func ProveBatchSchnorr(secrets []*big.Int, publicPoints []*curve.Point, c curve.Curve, context []byte) (*SchnorrBatchProof, error) {
	if len(secrets) != len(publicPoints) {
		return nil, ErrMismatchedLengths
	}

	proofs := make([]*SchnorrProof, len(secrets))

	for i := 0; i < len(secrets); i++ {
		proof, err := ProveSchnorr(secrets[i], publicPoints[i], c, context)
		if err != nil {
			return nil, err
		}
		proofs[i] = proof
	}

	return &SchnorrBatchProof{
		Proofs: proofs,
	}, nil
}

// VerifyBatch verifies all proofs in the batch
func (sbp *SchnorrBatchProof) VerifyBatch(publicPoints []*curve.Point, context []byte) bool {
	if len(sbp.Proofs) != len(publicPoints) {
		return false
	}

	for i := 0; i < len(sbp.Proofs); i++ {
		if !sbp.Proofs[i].Verify(publicPoints[i], context) {
			return false
		}
	}

	return true
}

// DLogEqualityProof proves that two points have the same discrete log
// Proves: Y1 = x*G1 and Y2 = x*G2 for the same secret x
type DLogEqualityProof struct {
	// Commitment1 is k*G1
	Commitment1 *curve.Point

	// Commitment2 is k*G2
	Commitment2 *curve.Point

	// Challenge is the Fiat-Shamir challenge
	Challenge *big.Int

	// Response is z = k + e*x
	Response *big.Int

	// Curve for operations
	Curve curve.Curve
}

// ProveDLogEquality creates a proof that two points share the same discrete log
func ProveDLogEquality(secret *big.Int, base1, base2, public1, public2 *curve.Point, c curve.Curve, context []byte) (*DLogEqualityProof, error) {
	if secret == nil {
		return nil, ErrNilSecret
	}

	// Verify witness: public1 = secret * base1 and public2 = secret * base2
	expected1, err := c.ScalarMult(base1, secret)
	if err != nil {
		return nil, err
	}
	expected2, err := c.ScalarMult(base2, secret)
	if err != nil {
		return nil, err
	}

	if !expected1.IsEqual(public1) || !expected2.IsEqual(public2) {
		return nil, ErrInvalidWitness
	}

	// Generate random nonce
	order := c.Order()
	k, err := rand.GenerateRandomScalar(order)
	if err != nil {
		return nil, err
	}

	// Commitments: R1 = k*G1, R2 = k*G2
	commitment1, err := c.ScalarMult(base1, k)
	if err != nil {
		return nil, err
	}

	commitment2, err := c.ScalarMult(base2, k)
	if err != nil {
		return nil, err
	}

	// Compute challenge: e = H(G1, G2, Y1, Y2, R1, R2, context)
	transcript := make([]byte, 0, 512)
	transcript = append(transcript, base1.Bytes()...)
	transcript = append(transcript, base2.Bytes()...)
	transcript = append(transcript, public1.Bytes()...)
	transcript = append(transcript, public2.Bytes()...)
	transcript = append(transcript, commitment1.Bytes()...)
	transcript = append(transcript, commitment2.Bytes()...)
	transcript = append(transcript, context...)

	challenge := hash.FiatShamirChallenge(transcript, order)

	// Response: z = k + e*x
	ex := new(big.Int).Mul(challenge, secret)
	response := new(big.Int).Add(k, ex)
	response.Mod(response, order)

	// Secure cleanup
	security.SecureZero(k.Bytes())

	return &DLogEqualityProof{
		Commitment1: commitment1,
		Commitment2: commitment2,
		Challenge:   challenge,
		Response:    response,
		Curve:       c,
	}, nil
}

// Verify verifies the discrete log equality proof
func (dep *DLogEqualityProof) Verify(base1, base2, public1, public2 *curve.Point, context []byte) bool {
	if dep == nil {
		return false
	}

	// Recompute challenge
	transcript := make([]byte, 0, 512)
	transcript = append(transcript, base1.Bytes()...)
	transcript = append(transcript, base2.Bytes()...)
	transcript = append(transcript, public1.Bytes()...)
	transcript = append(transcript, public2.Bytes()...)
	transcript = append(transcript, dep.Commitment1.Bytes()...)
	transcript = append(transcript, dep.Commitment2.Bytes()...)
	transcript = append(transcript, context...)

	expectedChallenge := hash.FiatShamirChallenge(transcript, dep.Curve.Order())

	if !security.SecureCompareScalars(dep.Challenge, expectedChallenge) {
		return false
	}

	// Verify: z*G1 = R1 + e*Y1
	zG1, err := dep.Curve.ScalarMult(base1, dep.Response)
	if err != nil {
		return false
	}

	eY1, err := dep.Curve.ScalarMult(public1, dep.Challenge)
	if err != nil {
		return false
	}

	rightSide1, err := dep.Curve.Add(dep.Commitment1, eY1)
	if err != nil {
		return false
	}

	if !zG1.IsEqual(rightSide1) {
		return false
	}

	// Verify: z*G2 = R2 + e*Y2
	zG2, err := dep.Curve.ScalarMult(base2, dep.Response)
	if err != nil {
		return false
	}

	eY2, err := dep.Curve.ScalarMult(public2, dep.Challenge)
	if err != nil {
		return false
	}

	rightSide2, err := dep.Curve.Add(dep.Commitment2, eY2)
	if err != nil {
		return false
	}

	return zG2.IsEqual(rightSide2)
}

// CompactSchnorrProof is a space-optimized Schnorr proof
// Only stores Response and Challenge (Commitment can be recomputed)
type CompactSchnorrProof struct {
	Challenge *big.Int
	Response  *big.Int
}

// ToCompact converts a standard proof to compact form
func (sp *SchnorrProof) ToCompact() *CompactSchnorrProof {
	return &CompactSchnorrProof{
		Challenge: sp.Challenge,
		Response:  sp.Response,
	}
}

// VerifyCompact verifies a compact proof
func VerifyCompactSchnorr(proof *CompactSchnorrProof, publicPoint *curve.Point, c curve.Curve, context []byte) bool {
	if proof == nil || publicPoint == nil {
		return false
	}

	// Recompute commitment: R = z*G - e*Y
	zG, err := c.ScalarBaseMult(proof.Response)
	if err != nil {
		return false
	}

	eY, err := c.ScalarMult(publicPoint, proof.Challenge)
	if err != nil {
		return false
	}

	negEY, err := c.Negate(eY)
	if err != nil {
		return false
	}

	commitment, err := c.Add(zG, negEY)
	if err != nil {
		return false
	}

	// Recompute and verify challenge
	expectedChallenge := computeSchnorrChallenge(c, publicPoint, commitment, context)

	return security.SecureCompareScalars(proof.Challenge, expectedChallenge)
}
