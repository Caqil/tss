// Package math provides mathematical operations for cryptographic protocols
package math

import (
	"math/big"

	"github.com/Caqil/mpc-tss/pkg/crypto/rand"
)

// Polynomial represents a polynomial over a finite field (mod p)
// f(x) = coefficients[0] + coefficients[1]*x + coefficients[2]*x^2 + ...
type Polynomial struct {
	// Coefficients in ascending order (index 0 is constant term)
	Coefficients []*big.Int

	// Modulus is the field modulus (usually the curve order)
	Modulus *big.Int
}

// NewPolynomial creates a new polynomial with given coefficients
func NewPolynomial(coefficients []*big.Int, modulus *big.Int) (*Polynomial, error) {
	if len(coefficients) == 0 {
		return nil, ErrEmptyCoefficients
	}
	if modulus == nil || modulus.Sign() <= 0 {
		return nil, ErrInvalidModulus
	}

	// Normalize coefficients to field
	normalized := make([]*big.Int, len(coefficients))
	for i, coef := range coefficients {
		if coef == nil {
			normalized[i] = big.NewInt(0)
		} else {
			normalized[i] = new(big.Int).Mod(coef, modulus)
		}
	}

	return &Polynomial{
		Coefficients: normalized,
		Modulus:      modulus,
	}, nil
}

// NewRandomPolynomial generates a random polynomial of given degree
// The constant term (a₀) can be specified, other coefficients are random
func NewRandomPolynomial(degree int, constantTerm *big.Int, modulus *big.Int) (*Polynomial, error) {
	if degree < 0 {
		return nil, ErrInvalidDegree
	}
	if modulus == nil || modulus.Sign() <= 0 {
		return nil, ErrInvalidModulus
	}

	coefficients := make([]*big.Int, degree+1)

	// Set constant term
	if constantTerm != nil {
		coefficients[0] = new(big.Int).Mod(constantTerm, modulus)
	} else {
		var err error
		coefficients[0], err = rand.GenerateRandomScalar(modulus)
		if err != nil {
			return nil, err
		}
	}

	// Generate random coefficients for other terms
	for i := 1; i <= degree; i++ {
		coef, err := rand.GenerateRandomScalar(modulus)
		if err != nil {
			return nil, err
		}
		coefficients[i] = coef
	}

	return &Polynomial{
		Coefficients: coefficients,
		Modulus:      modulus,
	}, nil
}

// Degree returns the degree of the polynomial
func (p *Polynomial) Degree() int {
	// Find highest non-zero coefficient
	for i := len(p.Coefficients) - 1; i >= 0; i-- {
		if p.Coefficients[i].Sign() != 0 {
			return i
		}
	}
	return 0
}

// Evaluate evaluates the polynomial at point x: f(x) mod p
// Uses Horner's method for efficiency
func (p *Polynomial) Evaluate(x *big.Int) *big.Int {
	if x == nil {
		return big.NewInt(0)
	}

	n := len(p.Coefficients)
	if n == 0 {
		return big.NewInt(0)
	}

	// Normalize x to field
	xMod := new(big.Int).Mod(x, p.Modulus)

	// Horner's method: f(x) = a₀ + x(a₁ + x(a₂ + x(a₃ + ...)))
	result := new(big.Int).Set(p.Coefficients[n-1])

	for i := n - 2; i >= 0; i-- {
		result.Mul(result, xMod)
		result.Add(result, p.Coefficients[i])
		result.Mod(result, p.Modulus)
	}

	return result
}

// EvaluateMultiple evaluates the polynomial at multiple points
func (p *Polynomial) EvaluateMultiple(points []*big.Int) []*big.Int {
	results := make([]*big.Int, len(points))
	for i, point := range points {
		results[i] = p.Evaluate(point)
	}
	return results
}

// Add adds two polynomials: (f + g)(x) = f(x) + g(x)
func (p *Polynomial) Add(q *Polynomial) (*Polynomial, error) {
	if q == nil {
		return nil, ErrNilPolynomial
	}
	if p.Modulus.Cmp(q.Modulus) != 0 {
		return nil, ErrModulusMismatch
	}

	// Determine length of result
	maxLen := len(p.Coefficients)
	if len(q.Coefficients) > maxLen {
		maxLen = len(q.Coefficients)
	}

	coefficients := make([]*big.Int, maxLen)

	// Add coefficients
	for i := 0; i < maxLen; i++ {
		sum := big.NewInt(0)

		if i < len(p.Coefficients) {
			sum.Add(sum, p.Coefficients[i])
		}
		if i < len(q.Coefficients) {
			sum.Add(sum, q.Coefficients[i])
		}

		sum.Mod(sum, p.Modulus)
		coefficients[i] = sum
	}

	return &Polynomial{
		Coefficients: coefficients,
		Modulus:      p.Modulus,
	}, nil
}

// Sub subtracts two polynomials: (f - g)(x) = f(x) - g(x)
func (p *Polynomial) Sub(q *Polynomial) (*Polynomial, error) {
	if q == nil {
		return nil, ErrNilPolynomial
	}
	if p.Modulus.Cmp(q.Modulus) != 0 {
		return nil, ErrModulusMismatch
	}

	maxLen := len(p.Coefficients)
	if len(q.Coefficients) > maxLen {
		maxLen = len(q.Coefficients)
	}

	coefficients := make([]*big.Int, maxLen)

	for i := 0; i < maxLen; i++ {
		diff := big.NewInt(0)

		if i < len(p.Coefficients) {
			diff.Add(diff, p.Coefficients[i])
		}
		if i < len(q.Coefficients) {
			diff.Sub(diff, q.Coefficients[i])
		}

		diff.Mod(diff, p.Modulus)
		coefficients[i] = diff
	}

	return &Polynomial{
		Coefficients: coefficients,
		Modulus:      p.Modulus,
	}, nil
}

// ScalarMul multiplies polynomial by a scalar: (k*f)(x) = k * f(x)
func (p *Polynomial) ScalarMul(k *big.Int) (*Polynomial, error) {
	if k == nil {
		return nil, ErrNilScalar
	}

	coefficients := make([]*big.Int, len(p.Coefficients))

	for i, coef := range p.Coefficients {
		product := new(big.Int).Mul(coef, k)
		product.Mod(product, p.Modulus)
		coefficients[i] = product
	}

	return &Polynomial{
		Coefficients: coefficients,
		Modulus:      p.Modulus,
	}, nil
}

// Interpolate performs Lagrange interpolation to find polynomial
// passing through given points (x_i, y_i)
// Returns polynomial f such that f(x_i) = y_i for all i
func Interpolate(points []*big.Int, values []*big.Int, modulus *big.Int) (*Polynomial, error) {
	if len(points) != len(values) {
		return nil, ErrPointValueMismatch
	}
	if len(points) == 0 {
		return nil, ErrEmptyPoints
	}
	if modulus == nil || modulus.Sign() <= 0 {
		return nil, ErrInvalidModulus
	}

	// Initialize result polynomial as zero
	result := make([]*big.Int, len(points))
	for i := range result {
		result[i] = big.NewInt(0)
	}

	// Lagrange interpolation
	for i := 0; i < len(points); i++ {
		// Compute Lagrange basis polynomial L_i(x)
		basis := lagrangeBasis(i, points, modulus)

		// Multiply by y_i
		for j := 0; j < len(basis); j++ {
			term := new(big.Int).Mul(basis[j], values[i])
			term.Mod(term, modulus)

			result[j].Add(result[j], term)
			result[j].Mod(result[j], modulus)
		}
	}

	return &Polynomial{
		Coefficients: result,
		Modulus:      modulus,
	}, nil
}

// lagrangeBasis computes the i-th Lagrange basis polynomial
// L_i(x) = ∏_{j≠i} (x - x_j) / (x_i - x_j)
func lagrangeBasis(i int, points []*big.Int, modulus *big.Int) []*big.Int {
	// Start with polynomial "1"
	result := []*big.Int{big.NewInt(1)}

	for j := 0; j < len(points); j++ {
		if i == j {
			continue
		}

		// Compute denominator: (x_i - x_j) mod p
		denominator := new(big.Int).Sub(points[i], points[j])
		denominator.Mod(denominator, modulus)

		// Compute inverse of denominator
		invDenom := new(big.Int).ModInverse(denominator, modulus)
		if invDenom == nil {
			// Should not happen if points are distinct
			continue
		}

		// Multiply result by (x - x_j) / (x_i - x_j)
		// This means: result = result * [(x - x_j) * invDenom]
		result = multiplyByLinear(result, points[j], invDenom, modulus)
	}

	return result
}

// multiplyByLinear multiplies polynomial by (x - a) * scalar
func multiplyByLinear(poly []*big.Int, a, scalar, modulus *big.Int) []*big.Int {
	// (x - a) has coefficients [-a, 1]
	result := make([]*big.Int, len(poly)+1)
	for i := range result {
		result[i] = big.NewInt(0)
	}

	// Multiply each term by (x - a) * scalar
	for i := 0; i < len(poly); i++ {
		// poly[i] * x * scalar
		term1 := new(big.Int).Mul(poly[i], scalar)
		term1.Mod(term1, modulus)
		result[i+1].Add(result[i+1], term1)
		result[i+1].Mod(result[i+1], modulus)

		// poly[i] * (-a) * scalar
		term2 := new(big.Int).Mul(poly[i], a)
		term2.Mul(term2, scalar)
		term2.Neg(term2)
		term2.Mod(term2, modulus)
		result[i].Add(result[i], term2)
		result[i].Mod(result[i], modulus)
	}

	return result
}

// Clone creates a deep copy of the polynomial
func (p *Polynomial) Clone() *Polynomial {
	coefficients := make([]*big.Int, len(p.Coefficients))
	for i, coef := range p.Coefficients {
		coefficients[i] = new(big.Int).Set(coef)
	}

	return &Polynomial{
		Coefficients: coefficients,
		Modulus:      new(big.Int).Set(p.Modulus),
	}
}

// IsZero checks if polynomial is the zero polynomial
func (p *Polynomial) IsZero() bool {
	for _, coef := range p.Coefficients {
		if coef.Sign() != 0 {
			return false
		}
	}
	return true
}

// String returns a string representation of the polynomial (for debugging)
func (p *Polynomial) String() string {
	if p.IsZero() {
		return "0"
	}

	result := ""
	for i := len(p.Coefficients) - 1; i >= 0; i-- {
		if p.Coefficients[i].Sign() == 0 {
			continue
		}

		if result != "" {
			result += " + "
		}

		if i == 0 {
			result += p.Coefficients[i].String()
		} else if i == 1 {
			result += p.Coefficients[i].String() + "x"
		} else {
			result += p.Coefficients[i].String() + "x^" + string(rune(i+'0'))
		}
	}

	return result
}
