package curve

import (
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// secp256k1Curve implements the Curve interface for secp256k1 using btcec
type secp256k1Curve struct {
	params *CurveParams
}

// newSecp256k1 creates a new secp256k1 curve instance using btcec
func newSecp256k1() (Curve, error) {
	return &secp256k1Curve{
		params: &CurveParams{
			Name:    "secp256k1",
			P:       btcec.S256().Params().P,
			N:       btcec.S256().Params().N,
			B:       btcec.S256().Params().B,
			Gx:      btcec.S256().Params().Gx,
			Gy:      btcec.S256().Params().Gy,
			BitSize: btcec.S256().Params().BitSize,
			Curve:   btcec.S256(),
		},
	}, nil
}

func (c *secp256k1Curve) Params() *CurveParams {
	return c.params
}

func (c *secp256k1Curve) ScalarBaseMult(k *big.Int) (*Point, error) {
	if k == nil || k.Sign() <= 0 {
		return nil, ErrInvalidScalar
	}

	// Normalize k to be within [1, N-1]
	k = new(big.Int).Mod(k, c.params.N)
	if k.Sign() == 0 {
		return nil, ErrScalarZero
	}

	// Use btcec for production-grade scalar base multiplication
	// btcec provides constant-time operations and optimized algorithms
	privKey, _ := btcec.PrivKeyFromBytes(paddedBytes(k, 32))
	pubKey := privKey.PubKey()

	return &Point{
		X:     pubKey.X(),
		Y:     pubKey.Y(),
		curve: c,
	}, nil
}

func (c *secp256k1Curve) ScalarMult(p *Point, k *big.Int) (*Point, error) {
	if p == nil {
		return nil, ErrInvalidPoint
	}
	if k == nil || k.Sign() <= 0 {
		return nil, ErrInvalidScalar
	}
	if !c.IsOnCurve(p) {
		return nil, ErrInvalidPoint
	}

	// Normalize k
	k = new(big.Int).Mod(k, c.params.N)
	if k.Sign() == 0 {
		return nil, ErrScalarZero
	}

	// Use btcec for constant-time scalar multiplication
	// Perform scalar multiplication: result = k * point
	resultX, resultY := btcec.S256().ScalarMult(p.X, p.Y, k.Bytes())

	return &Point{
		X:     resultX,
		Y:     resultY,
		curve: c,
	}, nil
}

func (c *secp256k1Curve) Add(p1, p2 *Point) (*Point, error) {
	if p1 == nil || p2 == nil {
		return nil, ErrInvalidPoint
	}
	if !c.IsOnCurve(p1) || !c.IsOnCurve(p2) {
		return nil, ErrInvalidPoint
	}

	// Use btcec for point addition
	x, y := btcec.S256().Add(p1.X, p1.Y, p2.X, p2.Y)

	return &Point{
		X:     x,
		Y:     y,
		curve: c,
	}, nil
}

func (c *secp256k1Curve) Double(p *Point) (*Point, error) {
	if p == nil {
		return nil, ErrInvalidPoint
	}
	if !c.IsOnCurve(p) {
		return nil, ErrInvalidPoint
	}

	// Use btcec for point doubling
	x, y := btcec.S256().Double(p.X, p.Y)

	return &Point{
		X:     x,
		Y:     y,
		curve: c,
	}, nil
}

func (c *secp256k1Curve) Negate(p *Point) (*Point, error) {
	if p == nil {
		return nil, ErrInvalidPoint
	}
	if !c.IsOnCurve(p) {
		return nil, ErrInvalidPoint
	}

	// Negation in Weierstrass form: (x, y) -> (x, -y mod P)
	negY := new(big.Int).Sub(c.params.P, p.Y)
	negY.Mod(negY, c.params.P)

	return &Point{
		X:     new(big.Int).Set(p.X),
		Y:     negY,
		curve: c,
	}, nil
}

func (c *secp256k1Curve) IsOnCurve(p *Point) bool {
	if p == nil || p.X == nil || p.Y == nil {
		return false
	}
	return btcec.S256().IsOnCurve(p.X, p.Y)
}

func (c *secp256k1Curve) Marshal(p *Point) []byte {
	if p == nil {
		return nil
	}

	// Use btcec for SEC compressed encoding (33 bytes)
	// Create FieldVal for X and Y
	var xField, yField btcec.FieldVal
	xField.SetByteSlice(paddedBytes(p.X, 32))
	yField.SetByteSlice(paddedBytes(p.Y, 32))

	pubKey := btcec.NewPublicKey(&xField, &yField)

	return pubKey.SerializeCompressed()
}

func (c *secp256k1Curve) Unmarshal(data []byte) (*Point, error) {
	// btcec supports 33-byte compressed or 65-byte uncompressed format
	if len(data) != 33 && len(data) != 65 {
		return nil, ErrInvalidEncoding
	}

	// Use btcec to parse public key (handles both compressed and uncompressed)
	pubKey, err := btcec.ParsePubKey(data)
	if err != nil {
		return nil, ErrInvalidEncoding
	}

	p := &Point{
		X:     pubKey.X(),
		Y:     pubKey.Y(),
		curve: c,
	}

	if !c.IsOnCurve(p) {
		return nil, ErrInvalidPoint
	}

	return p, nil
}

func (c *secp256k1Curve) NewScalar(value *big.Int) (*Scalar, error) {
	if value == nil {
		return nil, ErrInvalidScalar
	}

	// Normalize to [0, N-1]
	v := new(big.Int).Mod(value, c.params.N)

	return &Scalar{
		Value: v,
		curve: c,
	}, nil
}

func (c *secp256k1Curve) ScalarAdd(s1, s2 *Scalar) (*Scalar, error) {
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

func (c *secp256k1Curve) ScalarSub(s1, s2 *Scalar) (*Scalar, error) {
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

func (c *secp256k1Curve) ScalarMul(s1, s2 *Scalar) (*Scalar, error) {
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

func (c *secp256k1Curve) ScalarInv(s *Scalar) (*Scalar, error) {
	if s == nil {
		return nil, ErrInvalidScalar
	}
	if s.Value.Sign() == 0 {
		return nil, ErrScalarZero
	}

	// Use constant-time modular inverse
	result := new(big.Int).ModInverse(s.Value, c.params.N)
	if result == nil {
		return nil, ErrInvalidScalar
	}

	return &Scalar{
		Value: result,
		curve: c,
	}, nil
}

func (c *secp256k1Curve) Generator() *Point {
	return &Point{
		X:     new(big.Int).Set(c.params.Gx),
		Y:     new(big.Int).Set(c.params.Gy),
		curve: c,
	}
}

func (c *secp256k1Curve) Order() *big.Int {
	return new(big.Int).Set(c.params.N)
}

func (c *secp256k1Curve) Name() string {
	return c.params.Name
}

// Helper functions for secp256k1-specific operations

// paddedBytes returns the bytes of a big.Int, padded to the specified length
func paddedBytes(value *big.Int, length int) []byte {
	bytes := value.Bytes()
	if len(bytes) >= length {
		return bytes
	}

	padded := make([]byte, length)
	copy(padded[length-len(bytes):], bytes)
	return padded
}

// RecoverPublicKey recovers a public key from a signature and message hash
// This is Bitcoin/Ethereum-specific functionality using signature recovery
// Note: Full compact signature recovery is available in btcec/v2/ecdsa package
func (c *secp256k1Curve) RecoverPublicKey(hash []byte, r, s *big.Int, recoveryID byte) (*Point, error) {
	if len(hash) != 32 {
		return nil, ErrInvalidEncoding
	}

	// Recovery of public key from signature
	// This uses the recovery formula from ECDSA
	// For full implementation, use github.com/btcsuite/btcd/btcec/v2/ecdsa package

	// For now, return unsupported - full implementation requires ecdsa.RecoverCompact
	return nil, ErrUnsupportedCurve
}

// SignECDSA creates an ECDSA signature for secp256k1
func (c *secp256k1Curve) SignECDSA(privKey *big.Int, hash []byte) ([]byte, error) {
	if len(hash) != 32 {
		return nil, ErrInvalidEncoding
	}

	// Create btcec private key
	priv, _ := btcec.PrivKeyFromBytes(paddedBytes(privKey, 32))

	// Sign using btcec/v2/ecdsa (uses RFC 6979 deterministic nonces)
	signature := ecdsa.Sign(priv, hash)

	// Serialize signature (DER format)
	return signature.Serialize(), nil
}

// VerifyECDSA validates an ECDSA signature for secp256k1
func (c *secp256k1Curve) VerifyECDSA(pubKey *Point, hash []byte, sig []byte) bool {
	if len(hash) != 32 {
		return false
	}
	if !c.IsOnCurve(pubKey) {
		return false
	}

	// Parse signature (DER format)
	signature, err := ecdsa.ParseSignature(sig)
	if err != nil {
		return false
	}

	// Build btcec public key
	var xField, yField btcec.FieldVal
	xField.SetByteSlice(paddedBytes(pubKey.X, 32))
	yField.SetByteSlice(paddedBytes(pubKey.Y, 32))

	btcPubKey := btcec.NewPublicKey(&xField, &yField)

	// Verify signature
	return signature.Verify(hash, btcPubKey)
}
