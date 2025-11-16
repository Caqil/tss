// Package keygen implements Feldman VSS (Verifiable Secret Sharing)
package keygen

import (
	"math/big"

	"github.com/Caqil/mpc-tss/internal/math"
	"github.com/Caqil/mpc-tss/internal/security"
	"github.com/Caqil/mpc-tss/pkg/crypto/curve"
)

// FeldmanVSS implements Feldman's Verifiable Secret Sharing scheme
// This allows verifying shares without revealing the secret
type FeldmanVSS struct {
	// Threshold is the minimum number of shares needed
	Threshold int

	// NumParties is the total number of parties
	NumParties int

	// Curve is the elliptic curve
	Curve curve.Curve

	// Polynomial is the sharing polynomial (kept private by dealer)
	Polynomial *math.Polynomial

	// Commitments are public commitments to polynomial coefficients
	// C_i = a_i * G where a_i is the i-th coefficient
	Commitments []*curve.Point
}

// NewFeldmanVSS creates a new Feldman VSS instance
func NewFeldmanVSS(threshold, numParties int, c curve.Curve) (*FeldmanVSS, error) {
	if err := security.ValidateThreshold(threshold, numParties); err != nil {
		return nil, err
	}

	if c == nil {
		return nil, ErrNilCurve
	}

	return &FeldmanVSS{
		Threshold:  threshold,
		NumParties: numParties,
		Curve:      c,
	}, nil
}

// Share distributes a secret using Feldman VSS
// Returns shares and public commitments for verification
func (fvss *FeldmanVSS) Share(secret *big.Int) ([]*math.Share, []*curve.Point, error) {
	if secret == nil {
		return nil, nil, ErrNilSecret
	}

	order := fvss.Curve.Order()

	// Create Shamir secret sharing
	sss, err := math.NewShamirSecretSharing(fvss.Threshold, fvss.NumParties, order)
	if err != nil {
		return nil, nil, err
	}

	// Split secret into shares
	shares, polynomial, err := sss.Split(secret)
	if err != nil {
		return nil, nil, err
	}

	// Store polynomial (dealer keeps this private)
	fvss.Polynomial = polynomial

	// Create public commitments to polynomial coefficients
	// C_i = a_i * G for each coefficient a_i
	commitments := make([]*curve.Point, fvss.Threshold)

	for i := 0; i < fvss.Threshold; i++ {
		coeff := polynomial.Coefficients[i]
		commitment, err := fvss.Curve.ScalarBaseMult(coeff)
		if err != nil {
			return nil, nil, err
		}
		commitments[i] = commitment
	}

	fvss.Commitments = commitments

	return shares, commitments, nil
}

// VerifyShare verifies that a share is consistent with public commitments
// This is the key feature of Feldman VSS
// Verifies: g^{f(i)} = ∏_{j=0}^{t-1} (C_j)^{i^j}
func (fvss *FeldmanVSS) VerifyShare(share *math.Share, commitments []*curve.Point) bool {
	if share == nil || len(commitments) == 0 {
		return false
	}

	// Compute expected commitment: g^{f(index)}
	// = C_0 * C_1^index * C_2^{index^2} * ... * C_{t-1}^{index^{t-1}}

	order := fvss.Curve.Order()
	expected := commitments[0].Clone()

	// indexPower = index^j
	indexPower := new(big.Int).Set(share.Index)

	for j := 1; j < len(commitments); j++ {
		// Compute C_j^{index^j}
		term, err := fvss.Curve.ScalarMult(commitments[j], indexPower)
		if err != nil {
			return false
		}

		// Multiply into result
		expected, err = fvss.Curve.Add(expected, term)
		if err != nil {
			return false
		}

		// Update index power for next iteration
		indexPower = new(big.Int).Mul(indexPower, share.Index)
		indexPower.Mod(indexPower, order)
	}

	// Compute actual commitment: g^{share.Value}
	actual, err := fvss.Curve.ScalarBaseMult(share.Value)
	if err != nil {
		return false
	}

	// Verify they match
	return actual.IsEqual(expected)
}

// Reconstruct recovers the secret from shares (must have ≥ threshold shares)
func (fvss *FeldmanVSS) Reconstruct(shares []*math.Share) (*big.Int, error) {
	if len(shares) < fvss.Threshold {
		return nil, ErrInsufficientShares
	}

	order := fvss.Curve.Order()

	sss, err := math.NewShamirSecretSharing(fvss.Threshold, fvss.NumParties, order)
	if err != nil {
		return nil, err
	}

	secret, err := sss.Combine(shares)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

// VerifyAndReconstruct verifies all shares before reconstruction
func (fvss *FeldmanVSS) VerifyAndReconstruct(shares []*math.Share, commitments []*curve.Point) (*big.Int, error) {
	// Verify each share
	for _, share := range shares {
		if !fvss.VerifyShare(share, commitments) {
			return nil, ErrInvalidShare
		}
	}

	// All shares valid, reconstruct
	return fvss.Reconstruct(shares)
}

// RefreshShares generates new shares for the same secret
// This is used for proactive security
func (fvss *FeldmanVSS) RefreshShares(oldShares []*math.Share, oldCommitments []*curve.Point) ([]*math.Share, []*curve.Point, error) {
	// First verify and reconstruct the secret
	secret, err := fvss.VerifyAndReconstruct(oldShares, oldCommitments)
	if err != nil {
		return nil, nil, err
	}

	// Generate new shares
	newShares, newCommitments, err := fvss.Share(secret)
	if err != nil {
		return nil, nil, err
	}

	// Securely zero the secret
	security.SecureZero(secret.Bytes())

	return newShares, newCommitments, nil
}

// GetPublicKey returns the public key (first commitment C_0 = secret * G)
func (fvss *FeldmanVSS) GetPublicKey() *curve.Point {
	if len(fvss.Commitments) == 0 {
		return nil
	}
	return fvss.Commitments[0]
}

// BatchVerifyShares verifies multiple shares efficiently
func (fvss *FeldmanVSS) BatchVerifyShares(shares []*math.Share, commitments []*curve.Point) []bool {
	results := make([]bool, len(shares))

	for i, share := range shares {
		results[i] = fvss.VerifyShare(share, commitments)
	}

	return results
}
