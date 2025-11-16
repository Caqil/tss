// Package signing - RFC 6979 deterministic nonce generation
package signing

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"math/big"
	"time"

	"github.com/Caqil/mpc-tss/internal/security"
	"github.com/Caqil/mpc-tss/pkg/crypto/curve"
)

// RFC6979NonceGenerator implements deterministic nonce generation per RFC 6979
// This prevents nonce reuse attacks while maintaining deterministic signatures
type RFC6979NonceGenerator struct {
	curve      curve.Curve
	hashFunc   func() hash.Hash
	privateKey *big.Int
}

// NewRFC6979NonceGenerator creates a new RFC 6979 nonce generator
func NewRFC6979NonceGenerator(privateKey *big.Int, c curve.Curve) *RFC6979NonceGenerator {
	return &RFC6979NonceGenerator{
		curve:      c,
		hashFunc:   sha256.New,
		privateKey: privateKey,
	}
}

// NewRFC6979NonceGeneratorSHA512 creates a new RFC 6979 nonce generator with SHA-512
func NewRFC6979NonceGeneratorSHA512(privateKey *big.Int, c curve.Curve) *RFC6979NonceGenerator {
	return &RFC6979NonceGenerator{
		curve:      c,
		hashFunc:   sha512.New,
		privateKey: privateKey,
	}
}

// GenerateNonce generates a deterministic nonce k for signing message hash
// Implements RFC 6979 Section 3.2
func (gen *RFC6979NonceGenerator) GenerateNonce(messageHash []byte) (*big.Int, error) {
	if len(messageHash) == 0 {
		return nil, ErrInvalidMessage
	}

	order := gen.curve.Order()
	qlen := order.BitLen()
	rlen := ((qlen + 7) / 8) * 8

	// Step a: Process message hash
	h1 := hashToInt(messageHash, order)

	// Step b: Convert private key to octets
	// x is the private key, converted to octet string of length rlen/8
	x := int2octets(gen.privateKey, order, rlen)

	// Step c: Convert hash to octets
	h1Octets := bits2octets(h1, order, qlen, rlen)

	// Step d: Initialize V = 0x01 0x01 0x01 ... (hlen/8 octets)
	hlen_bytes := gen.hashFunc().Size()
	V := make([]byte, hlen_bytes)
	for i := range V {
		V[i] = 0x01
	}

	// Step e: Initialize K = 0x00 0x00 0x00 ... (hlen/8 octets)
	K := make([]byte, hlen_bytes)

	// Step f: K = HMAC_K(V || 0x00 || x || h1)
	K = gen.hmacUpdate(K, V, 0x00, x, h1Octets)

	// Step g: V = HMAC_K(V)
	V = gen.hmacHash(K, V)

	// Step h: K = HMAC_K(V || 0x01 || x || h1)
	K = gen.hmacUpdate(K, V, 0x01, x, h1Octets)

	// Step i: V = HMAC_K(V)
	V = gen.hmacHash(K, V)

	// Step h: Generate k
	for {
		// Step h.1: Set T to empty sequence
		T := []byte{}

		// Step h.2: While len(T) < qlen
		for len(T)*8 < qlen {
			// V = HMAC_K(V)
			V = gen.hmacHash(K, V)
			// T = T || V
			T = append(T, V...)
		}

		// Step h.3: Compute k
		k := bits2int(T, qlen)
		k.Mod(k, order)

		// If k is in range [1, order-1], return it
		if k.Sign() > 0 && k.Cmp(order) < 0 {
			return k, nil
		}

		// Otherwise, update K and V and try again
		// K = HMAC_K(V || 0x00)
		K = gen.hmacUpdate(K, V, 0x00)
		// V = HMAC_K(V)
		V = gen.hmacHash(K, V)
	}
}

// hmacHash computes HMAC-Hash(key, data)
func (gen *RFC6979NonceGenerator) hmacHash(key, data []byte) []byte {
	h := hmac.New(gen.hashFunc, key)
	h.Write(data)
	return h.Sum(nil)
}

// hmacUpdate computes HMAC-Hash(key, V || marker || data...)
func (gen *RFC6979NonceGenerator) hmacUpdate(key, V []byte, marker byte, data ...[]byte) []byte {
	h := hmac.New(gen.hashFunc, key)
	h.Write(V)
	h.Write([]byte{marker})
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// hashToInt converts a hash to an integer modulo order
func hashToInt(hash []byte, order *big.Int) *big.Int {
	orderBits := order.BitLen()
	orderBytes := (orderBits + 7) / 8

	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}

	return ret
}

// bits2int converts a bit string to an integer per RFC 6979
func bits2int(b []byte, qlen int) *big.Int {
	blen := len(b) * 8
	v := new(big.Int).SetBytes(b)

	if blen > qlen {
		v.Rsh(v, uint(blen-qlen))
	}

	return v
}

// int2octets converts an integer to an octet string per RFC 6979
func int2octets(v *big.Int, order *big.Int, rlen int) []byte {
	out := v.Bytes()
	rolen := rlen / 8

	if len(out) < rolen {
		// Pad with zeros on the left
		padded := make([]byte, rolen)
		copy(padded[rolen-len(out):], out)
		return padded
	} else if len(out) > rolen {
		// Truncate from the left
		return out[len(out)-rolen:]
	}

	return out
}

// bits2octets converts a bit string to an octet string per RFC 6979
func bits2octets(b *big.Int, order *big.Int, qlen, rlen int) []byte {
	// z1 = bits2int(b, qlen)
	z1 := new(big.Int).Set(b)

	// z2 = z1 - order
	z2 := new(big.Int).Sub(z1, order)

	// If z2 < 0, use z1; otherwise use z2
	if z2.Sign() < 0 {
		return int2octets(z1, order, rlen)
	}
	return int2octets(z2, order, rlen)
}

// DeterministicSign signs a message using deterministic nonce (RFC 6979)
// This provides the same security as random nonces but is deterministic
func (t *ThresholdSigner) DeterministicSign(messageHash []byte) (*Signature, error) {
	if len(messageHash) != 32 {
		return nil, ErrInvalidMessage
	}

	// Create RFC 6979 nonce generator
	nonceGen := NewRFC6979NonceGenerator(t.keyShare.Share, t.curve)

	// Generate deterministic nonce
	k, err := nonceGen.GenerateNonce(messageHash)
	if err != nil {
		return nil, err
	}

	// Compute R = k * G
	R, err := t.curve.ScalarBaseMult(k)
	if err != nil {
		security.SecureZero(k.Bytes())
		return nil, err
	}

	// Validate R is on curve
	if !t.curve.IsOnCurve(R) {
		security.SecureZero(k.Bytes())
		return nil, ErrInvalidNonce
	}

	// Compute r = R.x mod n
	order := t.curve.Order()
	r := new(big.Int).Mod(R.X, order)

	if r.Sign() == 0 {
		security.SecureZero(k.Bytes())
		return nil, ErrInvalidR
	}

	// Convert message hash to scalar
	m := new(big.Int).SetBytes(messageHash)

	// Compute s = k^-1 * (m + r*x) mod n
	kInv := security.ConstantTimeModInv(k, order)
	if kInv == nil {
		security.SecureZero(k.Bytes())
		return nil, ErrInvalidNonce
	}

	// r * x
	rx := security.ConstantTimeModMul(r, t.keyShare.Share, order)

	// m + r*x
	mrx := security.ConstantTimeModAdd(m, rx, order)

	// k^-1 * (m + r*x)
	s := security.ConstantTimeModMul(kInv, mrx, order)

	// Apply low-s normalization (BIP 62)
	halfOrder := new(big.Int).Rsh(order, 1)
	if s.Cmp(halfOrder) > 0 {
		s = new(big.Int).Sub(order, s)
	}

	signature := &Signature{
		R: r,
		S: s,
	}

	// Verify the signature
	if !Verify(t.keyShare.PublicKey, messageHash, signature, t.curve) {
		security.SecureZero(k.Bytes())
		return nil, ErrInvalidSignature
	}

	// Securely zero the nonce
	security.SecureZero(k.Bytes())

	return signature, nil
}

// VerifyDeterministic verifies a deterministic signature
// This is the same as regular verification, included for API completeness
func VerifyDeterministic(publicKey *curve.Point, messageHash []byte, sig *Signature, c curve.Curve) bool {
	return Verify(publicKey, messageHash, sig, c)
}

// GenerateDeterministicNonce is a public wrapper for RFC 6979 nonce generation
// This can be used for testing or custom signing protocols
func GenerateDeterministicNonce(privateKey *big.Int, messageHash []byte, c curve.Curve) (*big.Int, error) {
	if privateKey == nil || len(messageHash) == 0 || c == nil {
		return nil, ErrInvalidMessage
	}

	gen := NewRFC6979NonceGenerator(privateKey, c)
	return gen.GenerateNonce(messageHash)
}

// GenerateDeterministicNonceSHA512 generates a nonce using SHA-512
func GenerateDeterministicNonceSHA512(privateKey *big.Int, messageHash []byte, c curve.Curve) (*big.Int, error) {
	if privateKey == nil || len(messageHash) == 0 || c == nil {
		return nil, ErrInvalidMessage
	}

	gen := NewRFC6979NonceGeneratorSHA512(privateKey, c)
	return gen.GenerateNonce(messageHash)
}

// DeterministicPreSign generates a pre-signature using RFC 6979
// Note: This reduces security slightly as nonces are deterministic
// Only use when true randomness is not available
func (t *ThresholdSigner) DeterministicPreSign(entropy []byte) (*PreSignature, error) {
	// Create deterministic nonce from entropy
	nonceGen := NewRFC6979NonceGenerator(t.keyShare.Share, t.curve)

	k, err := nonceGen.GenerateNonce(entropy)
	if err != nil {
		return nil, err
	}

	// Compute R = k * G
	R, err := t.curve.ScalarBaseMult(k)
	if err != nil {
		security.SecureZero(k.Bytes())
		return nil, err
	}

	if !t.curve.IsOnCurve(R) {
		security.SecureZero(k.Bytes())
		return nil, ErrInvalidNonce
	}

	// Compute r = R.x mod n
	order := t.curve.Order()
	r := new(big.Int).Mod(R.X, order)

	if r.Sign() == 0 {
		security.SecureZero(k.Bytes())
		return nil, ErrInvalidR
	}

	// Compute k^-1
	kInv := security.ConstantTimeModInv(k, order)
	if kInv == nil {
		security.SecureZero(k.Bytes())
		return nil, ErrInvalidNonce
	}

	// Generate ID from entropy
	id := sha256.Sum256(entropy)

	return &PreSignature{
		ID:        id[:],
		R:         R,
		r:         r,
		k:         k,
		kInv:      kInv,
		PartyID:   t.partyID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		used:      false,
	}, nil
}
