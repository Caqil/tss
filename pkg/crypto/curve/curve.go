// Package curve provides elliptic curve operations for threshold signatures.
// All implementations use constant-time operations to prevent timing attacks.
package curve

import (
	"crypto/elliptic"
	"math/big"
)

// CurveType represents the type of elliptic curve
type CurveType int

const (
	// Secp256k1 is the Bitcoin/Ethereum curve
	Secp256k1 CurveType = iota
	// P256 is the NIST P-256 curve
	P256
	// Ed25519 is the Edwards curve for EdDSA
	Ed25519
)

// Point represents a point on an elliptic curve
type Point struct {
	X     *big.Int
	Y     *big.Int
	curve Curve
}

// Scalar represents a scalar value in the curve's field
type Scalar struct {
	Value *big.Int
	curve Curve
}

// Curve defines the interface for elliptic curve operations
type Curve interface {
	// Params returns the curve parameters
	Params() *CurveParams

	// ScalarBaseMult computes k*G where G is the generator
	ScalarBaseMult(k *big.Int) (*Point, error)

	// ScalarMult computes k*P for point P
	ScalarMult(p *Point, k *big.Int) (*Point, error)

	// Add computes P1 + P2
	Add(p1, p2 *Point) (*Point, error)

	// Double computes 2*P
	Double(p *Point) (*Point, error)

	// Negate computes -P
	Negate(p *Point) (*Point, error)

	// IsOnCurve verifies if point P is on the curve
	IsOnCurve(p *Point) bool

	// Marshal encodes a point to bytes
	Marshal(p *Point) []byte

	// Unmarshal decodes bytes to a point
	Unmarshal(data []byte) (*Point, error)

	// NewScalar creates a new scalar in the field
	NewScalar(value *big.Int) (*Scalar, error)

	// ScalarAdd computes s1 + s2 mod n
	ScalarAdd(s1, s2 *Scalar) (*Scalar, error)

	// ScalarSub computes s1 - s2 mod n
	ScalarSub(s1, s2 *Scalar) (*Scalar, error)

	// ScalarMul computes s1 * s2 mod n
	ScalarMul(s1, s2 *Scalar) (*Scalar, error)

	// ScalarInv computes s^-1 mod n
	ScalarInv(s *Scalar) (*Scalar, error)

	// Generator returns the generator point
	Generator() *Point

	// Order returns the order of the curve
	Order() *big.Int

	// Name returns the curve name
	Name() string
}

// CurveParams contains the parameters of an elliptic curve
type CurveParams struct {
	// Name of the curve
	Name string

	// P is the prime field modulus
	P *big.Int

	// N is the order of the base point
	N *big.Int

	// B is the curve equation parameter (y^2 = x^3 + B for secp256k1)
	B *big.Int

	// Gx, Gy are the coordinates of the generator
	Gx, Gy *big.Int

	// BitSize is the size of the curve in bits
	BitSize int

	// Underlying elliptic.Curve (for standard curves)
	Curve elliptic.Curve
}

// NewCurve creates a new curve instance based on the curve type
func NewCurve(curveType CurveType) (Curve, error) {
	switch curveType {
	case Secp256k1:
		return newSecp256k1()
	case P256:
		return newP256()
	case Ed25519:
		return newEd25519()
	default:
		return nil, ErrUnsupportedCurve
	}
}

// IsEqual checks if two points are equal
func (p *Point) IsEqual(other *Point) bool {
	if p == nil || other == nil {
		return p == other
	}
	return p.X.Cmp(other.X) == 0 && p.Y.Cmp(other.Y) == 0
}

// IsInfinity checks if point is the point at infinity
func (p *Point) IsInfinity() bool {
	return p.X == nil && p.Y == nil
}

// Clone creates a deep copy of the point
func (p *Point) Clone() *Point {
	if p == nil {
		return nil
	}
	return &Point{
		X:     new(big.Int).Set(p.X),
		Y:     new(big.Int).Set(p.Y),
		curve: p.curve,
	}
}

// Bytes returns the compressed encoding of the point
func (p *Point) Bytes() []byte {
	if p.curve == nil {
		return nil
	}
	return p.curve.Marshal(p)
}

// IsEqual checks if two scalars are equal
func (s *Scalar) IsEqual(other *Scalar) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.Value.Cmp(other.Value) == 0
}

// Clone creates a deep copy of the scalar
func (s *Scalar) Clone() *Scalar {
	if s == nil {
		return nil
	}
	return &Scalar{
		Value: new(big.Int).Set(s.Value),
		curve: s.curve,
	}
}

// Bytes returns the big-endian encoding of the scalar
func (s *Scalar) Bytes() []byte {
	if s.Value == nil {
		return nil
	}
	return s.Value.Bytes()
}
