package curve

import (
	"crypto/elliptic"
	"math/big"
)

// p256Curve implements the Curve interface for NIST P-256
type p256Curve struct {
	params *CurveParams
	curve  elliptic.Curve
}

// newP256 creates a new P-256 curve instance
func newP256() (Curve, error) {
	stdCurve := elliptic.P256()
	params := stdCurve.Params()

	return &p256Curve{
		params: &CurveParams{
			Name:    "P-256",
			P:       params.P,
			N:       params.N,
			B:       params.B,
			Gx:      params.Gx,
			Gy:      params.Gy,
			BitSize: params.BitSize,
			Curve:   stdCurve,
		},
		curve: stdCurve,
	}, nil
}

func (c *p256Curve) Params() *CurveParams {
	return c.params
}

func (c *p256Curve) ScalarBaseMult(k *big.Int) (*Point, error) {
	if k == nil || k.Sign() <= 0 {
		return nil, ErrInvalidScalar
	}

	k = new(big.Int).Mod(k, c.params.N)
	if k.Sign() == 0 {
		return nil, ErrScalarZero
	}

	x, y := c.curve.ScalarBaseMult(k.Bytes())

	return &Point{
		X:     x,
		Y:     y,
		curve: c,
	}, nil
}

func (c *p256Curve) ScalarMult(p *Point, k *big.Int) (*Point, error) {
	if p == nil {
		return nil, ErrInvalidPoint
	}
	if k == nil || k.Sign() <= 0 {
		return nil, ErrInvalidScalar
	}
	if !c.IsOnCurve(p) {
		return nil, ErrInvalidPoint
	}

	k = new(big.Int).Mod(k, c.params.N)
	if k.Sign() == 0 {
		return nil, ErrScalarZero
	}

	x, y := c.curve.ScalarMult(p.X, p.Y, k.Bytes())

	return &Point{
		X:     x,
		Y:     y,
		curve: c,
	}, nil
}

func (c *p256Curve) Add(p1, p2 *Point) (*Point, error) {
	if p1 == nil || p2 == nil {
		return nil, ErrInvalidPoint
	}
	if !c.IsOnCurve(p1) || !c.IsOnCurve(p2) {
		return nil, ErrInvalidPoint
	}

	x, y := c.curve.Add(p1.X, p1.Y, p2.X, p2.Y)

	return &Point{
		X:     x,
		Y:     y,
		curve: c,
	}, nil
}

func (c *p256Curve) Double(p *Point) (*Point, error) {
	if p == nil {
		return nil, ErrInvalidPoint
	}
	if !c.IsOnCurve(p) {
		return nil, ErrInvalidPoint
	}

	x, y := c.curve.Double(p.X, p.Y)

	return &Point{
		X:     x,
		Y:     y,
		curve: c,
	}, nil
}

func (c *p256Curve) Negate(p *Point) (*Point, error) {
	if p == nil {
		return nil, ErrInvalidPoint
	}
	if !c.IsOnCurve(p) {
		return nil, ErrInvalidPoint
	}

	negY := new(big.Int).Sub(c.params.P, p.Y)
	negY.Mod(negY, c.params.P)

	return &Point{
		X:     new(big.Int).Set(p.X),
		Y:     negY,
		curve: c,
	}, nil
}

func (c *p256Curve) IsOnCurve(p *Point) bool {
	if p == nil || p.X == nil || p.Y == nil {
		return false
	}
	return c.curve.IsOnCurve(p.X, p.Y)
}

func (c *p256Curve) Marshal(p *Point) []byte {
	if p == nil {
		return nil
	}
	return elliptic.MarshalCompressed(c.curve, p.X, p.Y)
}

func (c *p256Curve) Unmarshal(data []byte) (*Point, error) {
	if len(data) != 33 && len(data) != 65 {
		return nil, ErrInvalidEncoding
	}

	x, y := elliptic.UnmarshalCompressed(c.curve, data)
	if x == nil {
		return nil, ErrInvalidEncoding
	}

	p := &Point{
		X:     x,
		Y:     y,
		curve: c,
	}

	if !c.IsOnCurve(p) {
		return nil, ErrInvalidPoint
	}

	return p, nil
}

func (c *p256Curve) NewScalar(value *big.Int) (*Scalar, error) {
	if value == nil {
		return nil, ErrInvalidScalar
	}

	v := new(big.Int).Mod(value, c.params.N)

	return &Scalar{
		Value: v,
		curve: c,
	}, nil
}

func (c *p256Curve) ScalarAdd(s1, s2 *Scalar) (*Scalar, error) {
	if s1 == nil || s2 == nil {
		return nil, ErrInvalidScalar
	}

	result := new(big.Int).Add(s1.Value, s2.Value)
	result.Mod(result, c.params.N)

	return &Scalar{
		Value: result,
		curve: c,
	}, nil
}

func (c *p256Curve) ScalarSub(s1, s2 *Scalar) (*Scalar, error) {
	if s1 == nil || s2 == nil {
		return nil, ErrInvalidScalar
	}

	result := new(big.Int).Sub(s1.Value, s2.Value)
	result.Mod(result, c.params.N)

	return &Scalar{
		Value: result,
		curve: c,
	}, nil
}

func (c *p256Curve) ScalarMul(s1, s2 *Scalar) (*Scalar, error) {
	if s1 == nil || s2 == nil {
		return nil, ErrInvalidScalar
	}

	result := new(big.Int).Mul(s1.Value, s2.Value)
	result.Mod(result, c.params.N)

	return &Scalar{
		Value: result,
		curve: c,
	}, nil
}

func (c *p256Curve) ScalarInv(s *Scalar) (*Scalar, error) {
	if s == nil {
		return nil, ErrInvalidScalar
	}
	if s.Value.Sign() == 0 {
		return nil, ErrScalarZero
	}

	result := new(big.Int).ModInverse(s.Value, c.params.N)
	if result == nil {
		return nil, ErrInvalidScalar
	}

	return &Scalar{
		Value: result,
		curve: c,
	}, nil
}

func (c *p256Curve) Generator() *Point {
	return &Point{
		X:     new(big.Int).Set(c.params.Gx),
		Y:     new(big.Int).Set(c.params.Gy),
		curve: c,
	}
}

func (c *p256Curve) Order() *big.Int {
	return new(big.Int).Set(c.params.N)
}

func (c *p256Curve) Name() string {
	return c.params.Name
}
