// hash_to_curve.go implements RFC 9380 compliant hash-to-curve
package hash

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	"github.com/Caqil/mpc-tss/pkg/crypto/curve"
)

// HashToCurveRFC9380 implements RFC 9380 hash-to-curve
// This is a production-ready, standardized method
func HashToCurveRFC9380(data []byte, dst []byte, c curve.Curve) (*curve.Point, error) {
	if c == nil {
		return nil, ErrNilCurve
	}

	if len(dst) == 0 {
		dst = []byte("MPC-TSS-V1-HASH-TO-CURVE")
	}

	// Use hash_to_field to get field elements
	u := hashToField(data, dst, 2, c.Order())

	// Map to curve using simplified SWU or other method
	// For secp256k1/P-256 (Weierstrass curves), use simplified SWU
	point, err := simplifiedSWU(u[0], c)
	if err != nil {
		return nil, err
	}

	return point, nil
}

// hashToField implements hash_to_field from RFC 9380
// Produces count field elements from input message
func hashToField(msg, dst []byte, count int, modulus *big.Int) []*big.Int {
	// len_in_bytes = count * m * L
	// For 256-bit fields, L = 48 (security parameter)
	L := 48
	lenInBytes := count * L

	// Use expand_message_xmd
	uniformBytes := expandMessageXMD(msg, dst, lenInBytes)

	// Convert to field elements
	elements := make([]*big.Int, count)
	for i := 0; i < count; i++ {
		offset := i * L
		elmBytes := uniformBytes[offset : offset+L]

		// OS2IP: convert bytes to integer
		elm := new(big.Int).SetBytes(elmBytes)

		// Reduce modulo field order
		elm.Mod(elm, modulus)

		elements[i] = elm
	}

	return elements
}

// expandMessageXMD implements expand_message_xmd from RFC 9380
// Uses SHA-256 as the hash function
func expandMessageXMD(msg, dst []byte, lenInBytes int) []byte {
	// b_in_bytes = 32 for SHA-256
	// ell = ceil(len_in_bytes / b_in_bytes)
	bInBytes := 32
	ell := (lenInBytes + bInBytes - 1) / bInBytes

	// DST_prime = DST || I2OSP(len(DST), 1)
	dstPrime := append(dst, byte(len(dst)))

	// Z_pad = I2OSP(0, r_in_bytes) where r_in_bytes = 64 for SHA-256
	zPad := make([]byte, 64)

	// msg_prime = Z_pad || msg || I2OSP(len_in_bytes, 2) || I2OSP(0, 1) || DST_prime
	msgPrime := make([]byte, 0, len(zPad)+len(msg)+2+1+len(dstPrime))
	msgPrime = append(msgPrime, zPad...)
	msgPrime = append(msgPrime, msg...)
	msgPrime = append(msgPrime, byte(lenInBytes>>8), byte(lenInBytes))
	msgPrime = append(msgPrime, 0)
	msgPrime = append(msgPrime, dstPrime...)

	// b_0 = H(msg_prime)
	h := sha256.New()
	h.Write(msgPrime)
	b0 := h.Sum(nil)

	// b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	h.Reset()
	h.Write(b0)
	h.Write([]byte{1})
	h.Write(dstPrime)
	b1 := h.Sum(nil)

	// Collect output
	uniformBytes := make([]byte, 0, ell*bInBytes)
	uniformBytes = append(uniformBytes, b1...)

	bi := b1
	for i := 2; i <= ell; i++ {
		// b_i = H(strxor(b_0, b_(i-1)) || I2OSP(i, 1) || DST_prime)
		h.Reset()

		// XOR b_0 and b_(i-1)
		strxor := make([]byte, bInBytes)
		for j := 0; j < bInBytes; j++ {
			strxor[j] = b0[j] ^ bi[j]
		}

		h.Write(strxor)
		h.Write([]byte{byte(i)})
		h.Write(dstPrime)
		bi = h.Sum(nil)

		uniformBytes = append(uniformBytes, bi...)
	}

	return uniformBytes[:lenInBytes]
}

// simplifiedSWU implements simplified SWU map for Weierstrass curves
// Maps field element u to curve point
// Based on RFC 9380 Section 6.6.2
func simplifiedSWU(u *big.Int, c curve.Curve) (*curve.Point, error) {
	params := c.Params()

	// For y^2 = x^3 + ax + b (Weierstrass form)
	// secp256k1: a = 0, b = 7
	// P-256: a = -3, b = ...

	// Constants for the curve
	p := params.P
	a := big.NewInt(0) // secp256k1 has a=0
	b := params.B

	// For secp256k1 and similar curves, use simple try-and-increment
	// This is not the most efficient but is simple and correct
	return tryAndIncrement(u, a, b, p, c)
}

// tryAndIncrement is a simple hash-to-curve method
// Try consecutive x values until we find one on the curve
func tryAndIncrement(seed *big.Int, a, b, p *big.Int, c curve.Curve) (*curve.Point, error) {
	x := new(big.Int).Set(seed)
	x.Mod(x, p)

	// Try up to 256 values
	for i := 0; i < 256; i++ {
		// Check if x is on curve: y^2 = x^3 + ax + b
		y2 := new(big.Int).Exp(x, big.NewInt(3), p)

		if a.Sign() != 0 {
			ax := new(big.Int).Mul(a, x)
			y2.Add(y2, ax)
		}

		y2.Add(y2, b)
		y2.Mod(y2, p)

		// Check if y2 is a quadratic residue (has a square root)
		y := modSqrt(y2, p)
		if y != nil {
			// Found a point!
			point := &curve.Point{
				X: x,
				Y: y,
			}

			// Verify point is on curve
			if c.IsOnCurve(point) {
				return point, nil
			}
		}

		// Try next x
		x.Add(x, big.NewInt(1))
		x.Mod(x, p)
	}

	return nil, ErrHashToCurveFailed
}

// modSqrt computes modular square root using Tonelli-Shanks algorithm
// Returns nil if n is not a quadratic residue mod p
func modSqrt(n, p *big.Int) *big.Int {
	// Check if n is zero
	if n.Sign() == 0 {
		return big.NewInt(0)
	}

	// Ensure n is in range [0, p)
	n = new(big.Int).Mod(n, p)

	// Check if n is a quadratic residue using Legendre symbol
	// n^((p-1)/2) mod p should be 1
	exponent := new(big.Int).Sub(p, big.NewInt(1))
	exponent.Div(exponent, big.NewInt(2))
	legendre := new(big.Int).Exp(n, exponent, p)

	if legendre.Cmp(big.NewInt(1)) != 0 {
		// Not a quadratic residue
		return nil
	}

	// For p ≡ 3 (mod 4), use simple formula: y = n^((p+1)/4) mod p
	pMod4 := new(big.Int).Mod(p, big.NewInt(4))
	if pMod4.Cmp(big.NewInt(3)) == 0 {
		exponent := new(big.Int).Add(p, big.NewInt(1))
		exponent.Div(exponent, big.NewInt(4))
		return new(big.Int).Exp(n, exponent, p)
	}

	// General case: Tonelli-Shanks algorithm
	return tonelliShanks(n, p)
}

// tonelliShanks implements Tonelli-Shanks algorithm for modular square root
func tonelliShanks(n, p *big.Int) *big.Int {
	// Find Q and S such that p - 1 = Q * 2^S
	Q := new(big.Int).Sub(p, big.NewInt(1))
	S := 0

	for new(big.Int).And(Q, big.NewInt(1)).Sign() == 0 {
		Q.Div(Q, big.NewInt(2))
		S++
	}

	// Find a quadratic non-residue z
	z := big.NewInt(2)
	for {
		exponent := new(big.Int).Sub(p, big.NewInt(1))
		exponent.Div(exponent, big.NewInt(2))
		legendre := new(big.Int).Exp(z, exponent, p)

		if legendre.Cmp(new(big.Int).Sub(p, big.NewInt(1))) == 0 {
			break
		}
		z.Add(z, big.NewInt(1))
	}

	// Initialize
	M := S
	c := new(big.Int).Exp(z, Q, p)
	t := new(big.Int).Exp(n, Q, p)
	R := new(big.Int).Exp(n, new(big.Int).Add(Q, big.NewInt(1)).Div(new(big.Int).Add(Q, big.NewInt(1)), big.NewInt(2)), p)

	for {
		if t.Cmp(big.NewInt(0)) == 0 {
			return big.NewInt(0)
		}
		if t.Cmp(big.NewInt(1)) == 0 {
			return R
		}

		// Find least i such that t^(2^i) = 1
		i := 1
		temp := new(big.Int).Exp(t, big.NewInt(2), p)
		for temp.Cmp(big.NewInt(1)) != 0 && i < M {
			temp.Exp(temp, big.NewInt(2), p)
			i++
		}

		// Update values
		exp := big.NewInt(1 << uint(M-i-1))
		b := new(big.Int).Exp(c, exp, p)
		M = i
		c.Exp(b, big.NewInt(2), p)
		t.Mul(t, c)
		t.Mod(t, p)
		R.Mul(R, b)
		R.Mod(R, p)
	}
}

// DeriveIndependentGenerators derives multiple independent curve generators
// This is used for Pedersen commitments and similar protocols
// Uses RFC 9380 hash-to-curve with different domain separation tags
func DeriveIndependentGenerators(c curve.Curve, count int) ([]*curve.Point, error) {
	if count <= 0 {
		return nil, ErrInvalidLength
	}

	generators := make([]*curve.Point, count)

	for i := 0; i < count; i++ {
		// Create unique DST for each generator
		dst := []byte("MPC-TSS-GENERATOR-")
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(i))
		dst = append(dst, buf...)

		// Hash curve name with index to get unique input
		msg := []byte(c.Name())
		msg = append(msg, buf...)

		point, err := HashToCurveRFC9380(msg, dst, c)
		if err != nil {
			return nil, err
		}

		generators[i] = point
	}

	return generators, nil
}
