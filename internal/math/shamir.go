// Package math implements Shamir Secret Sharing scheme
package math

import (
	"math/big"

	"github.com/Caqil/mpc-tss/internal/security"
)

// Share represents a single share in Shamir Secret Sharing
type Share struct {
	// Index is the x-coordinate (party ID, typically 1-indexed)
	Index *big.Int

	// Value is the y-coordinate (f(index))
	Value *big.Int
}

// ShamirSecretSharing implements (t, n) threshold secret sharing
type ShamirSecretSharing struct {
	// Threshold is the minimum number of shares needed to reconstruct
	Threshold int

	// NumShares is the total number of shares
	NumShares int

	// Modulus is the field modulus (typically curve order)
	Modulus *big.Int
}

// NewShamirSecretSharing creates a new Shamir Secret Sharing instance
func NewShamirSecretSharing(threshold, numShares int, modulus *big.Int) (*ShamirSecretSharing, error) {
	if err := security.ValidateThreshold(threshold, numShares); err != nil {
		return nil, err
	}

	if modulus == nil || modulus.Sign() <= 0 {
		return nil, ErrInvalidModulus
	}

	return &ShamirSecretSharing{
		Threshold: threshold,
		NumShares: numShares,
		Modulus:   modulus,
	}, nil
}

// Split splits a secret into n shares where t are needed to reconstruct
// Returns shares where share i is (i+1, f(i+1)) for i = 0..n-1
func (sss *ShamirSecretSharing) Split(secret *big.Int) ([]*Share, *Polynomial, error) {
	if secret == nil {
		return nil, nil, ErrNilSecret
	}

	// Normalize secret to field
	secretMod := new(big.Int).Mod(secret, sss.Modulus)

	// Create random polynomial of degree (t-1) with constant term = secret
	// f(x) = secret + a₁x + a₂x² + ... + a_{t-1}x^{t-1}
	polynomial, err := NewRandomPolynomial(sss.Threshold-1, secretMod, sss.Modulus)
	if err != nil {
		return nil, nil, err
	}

	// Generate shares: share_i = (i, f(i)) for i = 1, 2, ..., n
	shares := make([]*Share, sss.NumShares)
	for i := 0; i < sss.NumShares; i++ {
		// Use 1-indexed party IDs (i+1) to avoid division by zero in reconstruction
		index := big.NewInt(int64(i + 1))
		value := polynomial.Evaluate(index)

		shares[i] = &Share{
			Index: index,
			Value: value,
		}
	}

	return shares, polynomial, nil
}

// Combine reconstructs the secret from t or more shares
// Uses Lagrange interpolation to recover f(0) = secret
func (sss *ShamirSecretSharing) Combine(shares []*Share) (*big.Int, error) {
	if len(shares) < sss.Threshold {
		return nil, ErrInsufficientShares
	}

	if len(shares) > sss.NumShares {
		return nil, ErrTooManyShares
	}

	// Take exactly t shares (if more provided, use first t)
	selectedShares := shares[:sss.Threshold]

	// Extract points and values for interpolation
	points := make([]*big.Int, sss.Threshold)
	values := make([]*big.Int, sss.Threshold)

	for i, share := range selectedShares {
		if share == nil {
			return nil, ErrNilShare
		}
		points[i] = share.Index
		values[i] = share.Value
	}

	// Verify no duplicate indices
	if hasDuplicates(points) {
		return nil, ErrDuplicatePoints
	}

	// Perform Lagrange interpolation to recover polynomial
	polynomial, err := Interpolate(points, values, sss.Modulus)
	if err != nil {
		return nil, err
	}

	// Secret is the constant term f(0)
	secret := polynomial.Coefficients[0]

	return secret, nil
}

// CombineAtPoint evaluates the shared polynomial at a given point
// Useful for verifiable secret sharing
func (sss *ShamirSecretSharing) CombineAtPoint(shares []*Share, x *big.Int) (*big.Int, error) {
	if len(shares) < sss.Threshold {
		return nil, ErrInsufficientShares
	}

	if x == nil {
		return nil, ErrNilPoint
	}

	// Take exactly t shares
	selectedShares := shares[:sss.Threshold]

	// Use Lagrange interpolation formula directly at point x
	// f(x) = Σᵢ yᵢ * Lᵢ(x) where Lᵢ(x) = ∏ⱼ≠ᵢ (x - xⱼ)/(xᵢ - xⱼ)
	result := big.NewInt(0)

	for i := 0; i < len(selectedShares); i++ {
		// Compute Lagrange basis Lᵢ(x)
		basis := big.NewInt(1)

		for j := 0; j < len(selectedShares); j++ {
			if i == j {
				continue
			}

			// Numerator: (x - xⱼ)
			numerator := new(big.Int).Sub(x, selectedShares[j].Index)
			numerator.Mod(numerator, sss.Modulus)

			// Denominator: (xᵢ - xⱼ)
			denominator := new(big.Int).Sub(selectedShares[i].Index, selectedShares[j].Index)
			denominator.Mod(denominator, sss.Modulus)

			// Compute inverse of denominator
			invDenom := new(big.Int).ModInverse(denominator, sss.Modulus)
			if invDenom == nil {
				return nil, ErrInvalidShare
			}

			// basis *= numerator / denominator
			basis.Mul(basis, numerator)
			basis.Mul(basis, invDenom)
			basis.Mod(basis, sss.Modulus)
		}

		// result += yᵢ * Lᵢ(x)
		term := new(big.Int).Mul(selectedShares[i].Value, basis)
		term.Mod(term, sss.Modulus)

		result.Add(result, term)
		result.Mod(result, sss.Modulus)
	}

	return result, nil
}

// VerifyShare verifies that a share is valid given public commitments
// commitments[i] = g^{aᵢ} where f(x) = a₀ + a₁x + ... + a_{t-1}x^{t-1}
// Verifies: g^{f(index)} = ∏ᵢ (commitments[i])^{index^i}
// This is used in Feldman VSS
func VerifyShare(share *Share, commitments []*big.Int, modulus, generator, prime *big.Int) bool {
	if share == nil || len(commitments) == 0 {
		return false
	}

	// Compute g^{f(index)} using commitments
	// g^{f(index)} = g^{a₀} * (g^{a₁})^{index} * (g^{a₂})^{index²} * ...
	expected := big.NewInt(1)
	indexPower := big.NewInt(1)

	for i := 0; i < len(commitments); i++ {
		// commitment[i]^{index^i}
		term := new(big.Int).Exp(commitments[i], indexPower, prime)
		expected.Mul(expected, term)
		expected.Mod(expected, prime)

		// Update index^i for next iteration
		indexPower.Mul(indexPower, share.Index)
		indexPower.Mod(indexPower, modulus)
	}

	// Compute g^{share.Value}
	actual := new(big.Int).Exp(generator, share.Value, prime)

	// Verify equality
	return expected.Cmp(actual) == 0
}

// RefreshShares generates new shares for the same secret
// This is used for proactive security to prevent share accumulation attacks
func (sss *ShamirSecretSharing) RefreshShares(oldShares []*Share) ([]*Share, error) {
	// First reconstruct the secret
	secret, err := sss.Combine(oldShares)
	if err != nil {
		return nil, err
	}

	// Generate new shares with a new random polynomial
	newShares, _, err := sss.Split(secret)
	if err != nil {
		return nil, err
	}

	// Securely zero the secret
	security.SecureZero(secret.Bytes())

	return newShares, nil
}

// AddShares performs additive homomorphic operation on shares
// If share1 corresponds to secret1 and share2 corresponds to secret2,
// then share1 + share2 corresponds to secret1 + secret2
func AddShares(share1, share2 *Share, modulus *big.Int) (*Share, error) {
	if share1 == nil || share2 == nil {
		return nil, ErrNilShare
	}

	if share1.Index.Cmp(share2.Index) != 0 {
		return nil, ErrShareIndexMismatch
	}

	valueSum := new(big.Int).Add(share1.Value, share2.Value)
	valueSum.Mod(valueSum, modulus)

	return &Share{
		Index: new(big.Int).Set(share1.Index),
		Value: valueSum,
	}, nil
}

// ScalarMulShare multiplies a share by a scalar
// If share corresponds to secret, then k*share corresponds to k*secret
func ScalarMulShare(share *Share, scalar, modulus *big.Int) (*Share, error) {
	if share == nil {
		return nil, ErrNilShare
	}
	if scalar == nil {
		return nil, ErrNilScalar
	}

	valueMul := new(big.Int).Mul(share.Value, scalar)
	valueMul.Mod(valueMul, modulus)

	return &Share{
		Index: new(big.Int).Set(share.Index),
		Value: valueMul,
	}, nil
}

// hasDuplicates checks if slice contains duplicate values
func hasDuplicates(values []*big.Int) bool {
	seen := make(map[string]bool)
	for _, v := range values {
		key := v.String()
		if seen[key] {
			return true
		}
		seen[key] = true
	}
	return false
}

// Clone creates a deep copy of a share
func (s *Share) Clone() *Share {
	if s == nil {
		return nil
	}
	return &Share{
		Index: new(big.Int).Set(s.Index),
		Value: new(big.Int).Set(s.Value),
	}
}
