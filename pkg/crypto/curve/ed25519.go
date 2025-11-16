package curve

import (
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"math/big"

	"filippo.io/edwards25519"
)

// ed25519Curve implements the Curve interface for Ed25519 using filippo.io/edwards25519
type ed25519Curve struct {
	params *CurveParams
}

// Ed25519 curve parameters (Edwards curve: -x^2 + y^2 = 1 + d*x^2*y^2)
var (
	// Field prime: 2^255 - 19
	ed25519P = fromHexEd25519("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED")
	// Group order (L)
	ed25519N = fromHexEd25519("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED")
	// Curve parameter d = -121665/121666
	ed25519D = fromHexEd25519("52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3")
	// Generator point G
	ed25519Gx = fromHexEd25519("216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A")
	ed25519Gy = fromHexEd25519("6666666666666666666666666666666666666666666666666666666666666658")
)

// newEd25519 creates a new Ed25519 curve instance
func newEd25519() (Curve, error) {
	return &ed25519Curve{
		params: &CurveParams{
			Name:    "Ed25519",
			P:       ed25519P,
			N:       ed25519N,
			B:       ed25519D, // Using 'd' parameter for Edwards curves
			Gx:      ed25519Gx,
			Gy:      ed25519Gy,
			BitSize: 255,
			Curve:   nil, // Ed25519 doesn't use stdlib elliptic.Curve
		},
	}, nil
}

func (c *ed25519Curve) Params() *CurveParams {
	return c.params
}

func (c *ed25519Curve) ScalarBaseMult(k *big.Int) (*Point, error) {
	if k == nil || k.Sign() <= 0 {
		return nil, ErrInvalidScalar
	}

	// Normalize k to be within [1, L-1]
	k = new(big.Int).Mod(k, c.params.N)
	if k.Sign() == 0 {
		return nil, ErrScalarZero
	}

	// Convert to edwards25519.Scalar
	var scalar edwards25519.Scalar
	scalarBytes := paddedBytesEd25519(k, 32)
	if _, err := scalar.SetCanonicalBytes(scalarBytes); err != nil {
		return nil, err
	}

	// Perform scalar base multiplication: P = k * G
	point := new(edwards25519.Point).ScalarBaseMult(&scalar)

	// Convert to affine coordinates
	return ed25519PointToAffine(point)
}

func (c *ed25519Curve) ScalarMult(p *Point, k *big.Int) (*Point, error) {
	if p == nil {
		return nil, ErrInvalidPoint
	}
	if k == nil || k.Sign() <= 0 {
		return nil, ErrInvalidScalar
	}

	// Normalize k
	k = new(big.Int).Mod(k, c.params.N)
	if k.Sign() == 0 {
		return nil, ErrScalarZero
	}

	// Convert Point to edwards25519.Point
	edPoint, err := affineToEd25519Point(p)
	if err != nil {
		return nil, err
	}

	// Convert scalar
	var scalar edwards25519.Scalar
	scalarBytes := paddedBytesEd25519(k, 32)
	if _, err := scalar.SetCanonicalBytes(scalarBytes); err != nil {
		return nil, err
	}

	// Perform scalar multiplication: result = k * P
	result := new(edwards25519.Point).ScalarMult(&scalar, edPoint)

	return ed25519PointToAffine(result)
}

func (c *ed25519Curve) Add(p1, p2 *Point) (*Point, error) {
	if p1 == nil || p2 == nil {
		return nil, ErrInvalidPoint
	}

	// Convert to edwards25519.Point
	edP1, err := affineToEd25519Point(p1)
	if err != nil {
		return nil, err
	}

	edP2, err := affineToEd25519Point(p2)
	if err != nil {
		return nil, err
	}

	// Perform point addition
	result := new(edwards25519.Point).Add(edP1, edP2)

	return ed25519PointToAffine(result)
}

func (c *ed25519Curve) Double(p *Point) (*Point, error) {
	if p == nil {
		return nil, ErrInvalidPoint
	}

	// Convert to edwards25519.Point
	edP, err := affineToEd25519Point(p)
	if err != nil {
		return nil, err
	}

	// Double is just Add(p, p)
	result := new(edwards25519.Point).Add(edP, edP)

	return ed25519PointToAffine(result)
}

func (c *ed25519Curve) Negate(p *Point) (*Point, error) {
	if p == nil {
		return nil, ErrInvalidPoint
	}

	// Convert to edwards25519.Point
	edP, err := affineToEd25519Point(p)
	if err != nil {
		return nil, err
	}

	// Negate the point
	result := new(edwards25519.Point).Negate(edP)

	return ed25519PointToAffine(result)
}

func (c *ed25519Curve) IsOnCurve(p *Point) bool {
	if p == nil || p.X == nil || p.Y == nil {
		return false
	}

	// Verify Edwards curve equation: -x^2 + y^2 = 1 + d*x^2*y^2 (mod p)
	P := c.params.P
	d := c.params.B

	x2 := new(big.Int).Exp(p.X, big.NewInt(2), P)
	y2 := new(big.Int).Exp(p.Y, big.NewInt(2), P)

	// Left side: -x^2 + y^2
	left := new(big.Int).Sub(y2, x2)
	left.Mod(left, P)

	// Right side: 1 + d*x^2*y^2
	right := new(big.Int).Mul(d, x2)
	right.Mul(right, y2)
	right.Add(right, big.NewInt(1))
	right.Mod(right, P)

	return left.Cmp(right) == 0
}

func (c *ed25519Curve) Marshal(p *Point) []byte {
	if p == nil {
		return nil
	}

	// Convert to edwards25519.Point and encode
	edP, err := affineToEd25519Point(p)
	if err != nil {
		return nil
	}

	// Ed25519 compressed encoding (32 bytes)
	return edP.Bytes()
}

func (c *ed25519Curve) Unmarshal(data []byte) (*Point, error) {
	if len(data) != 32 {
		return nil, ErrInvalidEncoding
	}

	// Decode using edwards25519
	edP := new(edwards25519.Point)
	if _, err := edP.SetBytes(data); err != nil {
		return nil, ErrInvalidEncoding
	}

	return ed25519PointToAffine(edP)
}

func (c *ed25519Curve) NewScalar(value *big.Int) (*Scalar, error) {
	if value == nil {
		return nil, ErrInvalidScalar
	}

	// Normalize to [0, L-1]
	v := new(big.Int).Mod(value, c.params.N)

	return &Scalar{
		Value: v,
		curve: c,
	}, nil
}

func (c *ed25519Curve) ScalarAdd(s1, s2 *Scalar) (*Scalar, error) {
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

func (c *ed25519Curve) ScalarSub(s1, s2 *Scalar) (*Scalar, error) {
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

func (c *ed25519Curve) ScalarMul(s1, s2 *Scalar) (*Scalar, error) {
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

func (c *ed25519Curve) ScalarInv(s *Scalar) (*Scalar, error) {
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

func (c *ed25519Curve) Generator() *Point {
	return &Point{
		X:     new(big.Int).Set(c.params.Gx),
		Y:     new(big.Int).Set(c.params.Gy),
		curve: c,
	}
}

func (c *ed25519Curve) Order() *big.Int {
	return new(big.Int).Set(c.params.N)
}

func (c *ed25519Curve) Name() string {
	return c.params.Name
}

// Helper functions for Ed25519

func fromHexEd25519(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid hex string: " + s)
	}
	return b
}

func paddedBytesEd25519(value *big.Int, length int) []byte {
	bytes := value.Bytes()
	if len(bytes) >= length {
		return bytes[len(bytes)-length:]
	}

	padded := make([]byte, length)
	copy(padded[length-len(bytes):], bytes)
	return padded
}

// affineToEd25519Point converts our Point representation to edwards25519.Point
func affineToEd25519Point(p *Point) (*edwards25519.Point, error) {
	// Ed25519 points are encoded as 32 bytes (compressed Y coordinate with X sign bit)
	// We need to encode and then decode to convert properly

	// For now, use a simple encoding: Y coordinate with X sign in high bit
	yBytes := paddedBytesEd25519(p.Y, 32)

	// Set sign bit based on X coordinate parity
	if p.X.Bit(0) == 1 {
		yBytes[31] |= 0x80
	}

	edP := new(edwards25519.Point)
	if _, err := edP.SetBytes(yBytes); err != nil {
		return nil, err
	}

	return edP, nil
}

// ed25519PointToAffine converts edwards25519.Point to our Point representation
func ed25519PointToAffine(edP *edwards25519.Point) (*Point, error) {
	// Get encoded bytes
	encoded := edP.Bytes()

	// Decode coordinates
	// Y coordinate is the lower 255 bits
	y := new(big.Int).SetBytes(encoded[:32])
	y.And(y, new(big.Int).SetBytes([]byte{
		0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	}))

	// Recover X coordinate from Y using curve equation
	x, err := recoverXFromY(y, (encoded[31]&0x80) != 0)
	if err != nil {
		return nil, err
	}

	return &Point{
		X:     x,
		Y:     y,
		curve: nil, // Will be set by caller
	}, nil
}

// recoverXFromY recovers X coordinate from Y on Ed25519 curve
func recoverXFromY(y *big.Int, signBit bool) (*big.Int, error) {
	// Edwards equation: -x^2 + y^2 = 1 + d*x^2*y^2
	// Solving for x^2: x^2 = (y^2 - 1) / (d*y^2 + 1)

	p := ed25519P
	d := ed25519D

	y2 := new(big.Int).Exp(y, big.NewInt(2), p)

	// Numerator: y^2 - 1
	numerator := new(big.Int).Sub(y2, big.NewInt(1))
	numerator.Mod(numerator, p)

	// Denominator: d*y^2 + 1
	denominator := new(big.Int).Mul(d, y2)
	denominator.Add(denominator, big.NewInt(1))
	denominator.Mod(denominator, p)

	// x^2 = numerator / denominator
	denominatorInv := new(big.Int).ModInverse(denominator, p)
	if denominatorInv == nil {
		return nil, errors.New("cannot recover X: denominator has no inverse")
	}

	x2 := new(big.Int).Mul(numerator, denominatorInv)
	x2.Mod(x2, p)

	// Take square root
	x := modSqrtEd25519(x2, p)
	if x == nil {
		return nil, errors.New("cannot recover X: not a quadratic residue")
	}

	// Check sign bit and negate if needed
	if (x.Bit(0) == 1) != signBit {
		x.Sub(p, x)
	}

	return x, nil
}

// modSqrtEd25519 computes modular square root for Ed25519 field
// p ≡ 5 (mod 8), so we can use the special formula
func modSqrtEd25519(a, p *big.Int) *big.Int {
	// For p ≡ 5 (mod 8), use: x = a^((p+3)/8)
	// Then check if x^2 ≡ a (mod p), otherwise x = x * 2^((p-1)/4)

	// Compute candidate: a^((p+3)/8)
	exp := new(big.Int).Add(p, big.NewInt(3))
	exp.Div(exp, big.NewInt(8))
	x := new(big.Int).Exp(a, exp, p)

	// Check if x^2 ≡ a (mod p)
	x2 := new(big.Int).Exp(x, big.NewInt(2), p)
	if x2.Cmp(a) == 0 {
		return x
	}

	// Try x * 2^((p-1)/4)
	exp2 := new(big.Int).Sub(p, big.NewInt(1))
	exp2.Div(exp2, big.NewInt(4))
	sqrt2 := new(big.Int).Exp(big.NewInt(2), exp2, p)

	x.Mul(x, sqrt2)
	x.Mod(x, p)

	// Verify result
	x2 = new(big.Int).Exp(x, big.NewInt(2), p)
	if x2.Cmp(a) == 0 {
		return x
	}

	// Not a quadratic residue
	return nil
}

// SignEdDSA creates an EdDSA signature for Ed25519
func (c *ed25519Curve) SignEdDSA(privKeyScalar *big.Int, message []byte) ([]byte, error) {
	// Convert scalar to Ed25519 private key (32 bytes seed)
	seed := paddedBytesEd25519(privKeyScalar, 32)

	// Derive Ed25519 private key from seed using SHA-512
	h := sha512.Sum512(seed)
	privateKey := ed25519.NewKeyFromSeed(h[:32])

	// Sign message
	signature := ed25519.Sign(privateKey, message)

	return signature, nil
}

// VerifyEdDSA validates an EdDSA signature for Ed25519
func (c *ed25519Curve) VerifyEdDSA(pubKey *Point, message []byte, signature []byte) bool {
	if len(signature) != ed25519.SignatureSize {
		return false
	}

	// Encode public key
	publicKeyBytes := c.Marshal(pubKey)
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return false
	}

	// Verify signature
	return ed25519.Verify(publicKeyBytes, message, signature)
}
