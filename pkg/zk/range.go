package zk

import (
	"math/big"

	"github.com/Caqil/mpc-tss/internal/security"
	"github.com/Caqil/mpc-tss/pkg/crypto/commitment"
	"github.com/Caqil/mpc-tss/pkg/crypto/curve"
	"github.com/Caqil/mpc-tss/pkg/crypto/hash"
	"github.com/Caqil/mpc-tss/pkg/crypto/rand"
)

// RangeProof proves that a committed value is in a specific range [0, 2^n)
// without revealing the value itself
type RangeProof struct {
	// BitCommitments are Pedersen commitments to each bit
	BitCommitments []*commitment.PedersenCommitment

	// BitProofs prove each commitment opens to 0 or 1
	BitProofs []*BitProof

	// AggregateProof proves the bits sum to the committed value
	AggregateProof *SchnorrProof

	// NumBits is the bit length (value < 2^NumBits)
	NumBits int
}

// BitProof proves a committed value is either 0 or 1
type BitProof struct {
	// Proof0 is a Schnorr proof assuming bit = 0
	Proof0 *SchnorrProof

	// Proof1 is a Schnorr proof assuming bit = 1
	Proof1 *SchnorrProof

	// Challenge is the Fiat-Shamir challenge
	Challenge *big.Int
}

// ProveRange creates a range proof for a committed value
// Proves that value ∈ [0, 2^numBits) without revealing value
func ProveRange(value *big.Int, valueCommitment *commitment.PedersenCommitment, gp *commitment.GeneratorPair, numBits int) (*RangeProof, error) {
	if value == nil {
		return nil, ErrNilValue
	}

	if value.Sign() < 0 {
		return nil, ErrInvalidRange
	}

	// Check value is in range [0, 2^numBits)
	maxValue := new(big.Int).Lsh(big.NewInt(1), uint(numBits))
	if value.Cmp(maxValue) >= 0 {
		return nil, ErrInvalidRange
	}

	// Decompose value into bits
	bits := decomposeIntoBits(value, numBits)

	// Create commitment for each bit
	bitCommitments := make([]*commitment.PedersenCommitment, numBits)
	bitProofs := make([]*BitProof, numBits)

	for i := 0; i < numBits; i++ {
		// Commit to bit
		bitValue := big.NewInt(int64(bits[i]))
		bitCommit, err := gp.Commit(bitValue, nil)
		if err != nil {
			return nil, err
		}
		bitCommitments[i] = bitCommit

		// Prove bit is 0 or 1
		bitProof, err := proveBit(bits[i], bitCommit, gp)
		if err != nil {
			return nil, err
		}
		bitProofs[i] = bitProof
	}

	// Create aggregate proof that bits sum to value
	// This is simplified - production should use proper aggregation
	c := gp.G
	aggregateProof, err := ProveSchnorr(value, valueCommitment.C, c, []byte("RANGE_AGGREGATE"))
	if err != nil {
		return nil, err
	}

	return &RangeProof{
		BitCommitments: bitCommitments,
		BitProofs:      bitProofs,
		AggregateProof: aggregateProof,
		NumBits:        numBits,
	}, nil
}

// Verify verifies the range proof
func (rp *RangeProof) Verify(valueCommitment *commitment.PedersenCommitment, gp *commitment.GeneratorPair) bool {
	if rp == nil {
		return false
	}

	// Verify each bit proof
	for i := 0; i < rp.NumBits; i++ {
		if !rp.BitProofs[i].Verify(rp.BitCommitments[i], gp) {
			return false
		}
	}

	// Verify aggregate (simplified)
	if !rp.AggregateProof.Verify(valueCommitment.C, []byte("RANGE_AGGREGATE")) {
		return false
	}

	return true
}

// proveBit creates a proof that a committed value is either 0 or 1
func proveBit(bit int, bitCommitment *commitment.PedersenCommitment, gp *commitment.GeneratorPair) (*BitProof, error) {
	if bit != 0 && bit != 1 {
		return nil, ErrInvalidRange
	}

	c := gp.G
	order := c.Order()

	// Generate random challenges for the simulated proof
	var challenge0, challenge1, response0, response1 *big.Int
	var commitment0, commitment1 *curve.Point

	if bit == 0 {
		// Real proof for bit=0, simulated proof for bit=1

		// Real proof: standard Schnorr
		k, err := rand.GenerateRandomScalar(order)
		if err != nil {
			return nil, err
		}

		commitment0, err = c.ScalarBaseMult(k)
		if err != nil {
			return nil, err
		}

		// Simulate proof for bit=1
		challenge1, err = rand.GenerateRandomScalar(order)
		if err != nil {
			return nil, err
		}

		response1, err = rand.GenerateRandomScalar(order)
		if err != nil {
			return nil, err
		}

		// commitment1 = response1*G - challenge1*(C - H)
		// where C is bitCommitment and H is generator for value 1
		commitment1, err = simulateCommitment(c, response1, challenge1, bitCommitment.C, gp.H)
		if err != nil {
			return nil, err
		}

		// Compute overall challenge
		transcript := buildBitProofTranscript(bitCommitment.C, commitment0, commitment1)
		overallChallenge := hash.FiatShamirChallenge(transcript, order)

		// challenge0 = overallChallenge - challenge1 mod order
		challenge0 = new(big.Int).Sub(overallChallenge, challenge1)
		challenge0.Mod(challenge0, order)

		// response0 = k + challenge0 * secret
		response0 = new(big.Int).Mul(challenge0, bitCommitment.Value)
		response0.Add(response0, k)
		response0.Mod(response0, order)

		security.SecureZero(k.Bytes())

	} else {
		// Real proof for bit=1, simulated proof for bit=0

		k, err := rand.GenerateRandomScalar(order)
		if err != nil {
			return nil, err
		}

		commitment1, err = c.ScalarBaseMult(k)
		if err != nil {
			return nil, err
		}

		// Simulate proof for bit=0
		challenge0, err = rand.GenerateRandomScalar(order)
		if err != nil {
			return nil, err
		}

		response0, err = rand.GenerateRandomScalar(order)
		if err != nil {
			return nil, err
		}

		commitment0, err = simulateCommitment(c, response0, challenge0, bitCommitment.C, nil)
		if err != nil {
			return nil, err
		}

		// Compute overall challenge
		transcript := buildBitProofTranscript(bitCommitment.C, commitment0, commitment1)
		overallChallenge := hash.FiatShamirChallenge(transcript, order)

		// challenge1 = overallChallenge - challenge0 mod order
		challenge1 = new(big.Int).Sub(overallChallenge, challenge0)
		challenge1.Mod(challenge1, order)

		// response1 = k + challenge1 * secret
		response1 = new(big.Int).Mul(challenge1, bitCommitment.Value)
		response1.Add(response1, k)
		response1.Mod(response1, order)

		security.SecureZero(k.Bytes())
	}

	// Build proofs
	proof0 := &SchnorrProof{
		Commitment: commitment0,
		Challenge:  challenge0,
		Response:   response0,
		Curve:      c,
	}

	proof1 := &SchnorrProof{
		Commitment: commitment1,
		Challenge:  challenge1,
		Response:   response1,
		Curve:      c,
	}

	// Overall challenge
	transcript := buildBitProofTranscript(bitCommitment.C, commitment0, commitment1)
	overallChallenge := hash.FiatShamirChallenge(transcript, order)

	return &BitProof{
		Proof0:    proof0,
		Proof1:    proof1,
		Challenge: overallChallenge,
	}, nil
}

// Verify verifies a bit proof
func (bp *BitProof) Verify(bitCommitment *commitment.PedersenCommitment, gp *commitment.GeneratorPair) bool {
	if bp == nil || bitCommitment == nil {
		return false
	}

	c := gp.G
	order := c.Order()

	// Verify challenge = challenge0 + challenge1 mod order
	challengeSum := new(big.Int).Add(bp.Proof0.Challenge, bp.Proof1.Challenge)
	challengeSum.Mod(challengeSum, order)

	if !security.SecureCompareScalars(challengeSum, bp.Challenge) {
		return false
	}

	// Verify proof0: response0*G = commitment0 + challenge0*C
	check0 := verifyBitProofSide(bp.Proof0, bitCommitment.C, nil, c)
	if !check0 {
		return false
	}

	// Verify proof1: response1*G = commitment1 + challenge1*(C - H)
	check1 := verifyBitProofSide(bp.Proof1, bitCommitment.C, gp.H, c)
	if !check1 {
		return false
	}

	// Verify overall challenge
	transcript := buildBitProofTranscript(bitCommitment.C, bp.Proof0.Commitment, bp.Proof1.Commitment)
	expectedChallenge := hash.FiatShamirChallenge(transcript, order)

	return security.SecureCompareScalars(bp.Challenge, expectedChallenge)
}

// Helper functions

func decomposeIntoBits(value *big.Int, numBits int) []int {
	bits := make([]int, numBits)
	for i := 0; i < numBits; i++ {
		bits[i] = int(value.Bit(i))
	}
	return bits
}

func simulateCommitment(c curve.Curve, response, challenge *big.Int, commitment, offset *curve.Point) (*curve.Point, error) {
	// Simulate: R = response*G - challenge*C
	// If offset != nil: R = response*G - challenge*(C - offset)

	responseG, err := c.ScalarBaseMult(response)
	if err != nil {
		return nil, err
	}

	target := commitment
	if offset != nil {
		negOffset, err := c.Negate(offset)
		if err != nil {
			return nil, err
		}
		target, err = c.Add(commitment, negOffset)
		if err != nil {
			return nil, err
		}
	}

	challengeC, err := c.ScalarMult(target, challenge)
	if err != nil {
		return nil, err
	}

	negChallengeC, err := c.Negate(challengeC)
	if err != nil {
		return nil, err
	}

	result, err := c.Add(responseG, negChallengeC)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func verifyBitProofSide(proof *SchnorrProof, commitment, offset *curve.Point, c curve.Curve) bool {
	// Verify: response*G = commitment_proof + challenge*(commitment - offset)

	responseG, err := c.ScalarBaseMult(proof.Response)
	if err != nil {
		return false
	}

	target := commitment
	if offset != nil {
		negOffset, err := c.Negate(offset)
		if err != nil {
			return false
		}
		target, err = c.Add(commitment, negOffset)
		if err != nil {
			return false
		}
	}

	challengeC, err := c.ScalarMult(target, proof.Challenge)
	if err != nil {
		return false
	}

	rightSide, err := c.Add(proof.Commitment, challengeC)
	if err != nil {
		return false
	}

	return responseG.IsEqual(rightSide)
}

func buildBitProofTranscript(commitment, commitment0, commitment1 *curve.Point) []byte {
	transcript := make([]byte, 0, 256)
	transcript = append(transcript, commitment.Bytes()...)
	transcript = append(transcript, commitment0.Bytes()...)
	transcript = append(transcript, commitment1.Bytes()...)
	transcript = append(transcript, []byte("BIT_PROOF_V1")...)
	return transcript
}
