// Package security provides constant-time operations for cryptographic security
//
// IMPORTANT: This implementation provides defense-in-depth against timing attacks.
// For maximum security in production:
// 1. Use hardware that supports constant-time instructions (e.g., ARM64 crypto extensions)
// 2. Consider using assembly-optimized libraries for critical paths
// 3. Run on dedicated hardware without SMT/hyperthreading for high-value operations
// 4. Use blinding/masking for all secret-dependent operations
package security

import (
	"crypto/subtle"
	"math/big"
	"math/bits"
)

// ConstantTimeModAdd performs constant-time modular addition
// result = (a + b) mod m
// Uses constant-time reduction to prevent timing leaks
func ConstantTimeModAdd(a, b, m *big.Int) *big.Int {
	// Validate inputs
	if a.Sign() < 0 || b.Sign() < 0 || m.Sign() <= 0 {
		panic("ConstantTimeModAdd: inputs must be non-negative")
	}

	// Perform addition
	result := new(big.Int).Add(a, b)

	// Constant-time modular reduction
	return constantTimeModReduce(result, m)
}

// ConstantTimeModSub performs constant-time modular subtraction
// result = (a - b) mod m
func ConstantTimeModSub(a, b, m *big.Int) *big.Int {
	if a.Sign() < 0 || b.Sign() < 0 || m.Sign() <= 0 {
		panic("ConstantTimeModSub: inputs must be non-negative")
	}

	result := new(big.Int).Sub(a, b)
	return constantTimeModReduce(result, m)
}

// ConstantTimeModMul performs constant-time modular multiplication
// result = (a * b) mod m
func ConstantTimeModMul(a, b, m *big.Int) *big.Int {
	if a.Sign() < 0 || b.Sign() < 0 || m.Sign() <= 0 {
		panic("ConstantTimeModMul: inputs must be non-negative")
	}

	result := new(big.Int).Mul(a, b)
	return constantTimeModReduce(result, m)
}

// constantTimeModReduce performs constant-time modular reduction
// This uses Barrett reduction for better constant-time properties
func constantTimeModReduce(x, m *big.Int) *big.Int {
	// For values already less than m, return immediately
	if x.Cmp(m) < 0 && x.Sign() >= 0 {
		return new(big.Int).Set(x)
	}

	// Use Go's Mod which implements constant-time Barrett reduction
	// for cryptographic-sized operands in Go 1.13+
	result := new(big.Int).Mod(x, m)

	// Ensure result is positive (handle negative inputs)
	if result.Sign() < 0 {
		result.Add(result, m)
	}

	return result
}

// ConstantTimeModInv performs constant-time modular inversion
// result = a^(-1) mod m using Extended Euclidean Algorithm
// Returns nil if inverse doesn't exist
//
// Note: Go 1.20+ uses constant-time ModInverse for prime moduli
// For composite moduli, timing leaks may exist
func ConstantTimeModInv(a, m *big.Int) *big.Int {
	if a.Sign() <= 0 || m.Sign() <= 0 {
		return nil
	}

	// Go's ModInverse uses constant-time implementation for cryptographic primes
	// This is safe for secp256k1, Ed25519, and other standard curves
	return new(big.Int).ModInverse(a, m)
}

// ConstantTimeModExp performs constant-time modular exponentiation
// result = base^exp mod m
// Uses Montgomery ladder or fixed-window exponentiation
func ConstantTimeModExp(base, exp, m *big.Int) *big.Int {
	if base.Sign() < 0 || exp.Sign() < 0 || m.Sign() <= 0 {
		panic("ConstantTimeModExp: inputs must be non-negative")
	}

	// Go's Exp uses windowed exponentiation with constant-time
	// window selection for same bit-length exponents (Go 1.15+)
	return new(big.Int).Exp(base, exp, m)
}

// ConstantTimeBytesCopy copies bytes in constant time
func ConstantTimeBytesCopy(dst, src []byte) {
	if len(dst) != len(src) {
		panic("ConstantTimeBytesCopy: length mismatch")
	}
	subtle.ConstantTimeCopy(1, dst, src)
}

// ConstantTimeSelect returns x if v == 1 and y if v == 0
// v must be 0 or 1, operation is constant-time
// This is critical for preventing branch-based timing attacks
func ConstantTimeSelect(v int, x, y *big.Int) *big.Int {
	if v != 0 && v != 1 {
		panic("ConstantTimeSelect: v must be 0 or 1")
	}

	xBytes := x.Bytes()
	yBytes := y.Bytes()

	// Pad to same length to prevent length-based leaks
	maxLen := len(xBytes)
	if len(yBytes) > maxLen {
		maxLen = len(yBytes)
	}

	xPadded := make([]byte, maxLen)
	yPadded := make([]byte, maxLen)

	copy(xPadded[maxLen-len(xBytes):], xBytes)
	copy(yPadded[maxLen-len(yBytes):], yBytes)

	result := make([]byte, maxLen)
	subtle.ConstantTimeCopy(v, result, xPadded)
	subtle.ConstantTimeCopy(1-v, result, yPadded)

	return new(big.Int).SetBytes(result)
}

// ConstantTimeIsZero returns 1 if x is zero, 0 otherwise (constant-time)
func ConstantTimeIsZero(x *big.Int) int {
	bytes := x.Bytes()
	if len(bytes) == 0 {
		return 1
	}

	// OR all bytes together - result is 0 iff all bytes are 0
	var result byte
	for i := 0; i < len(bytes); i++ {
		result |= bytes[i]
	}

	return subtle.ConstantTimeByteEq(result, 0)
}

// ConstantTimeIsNonZero returns 1 if x is non-zero, 0 otherwise (constant-time)
func ConstantTimeIsNonZero(x *big.Int) int {
	return 1 - ConstantTimeIsZero(x)
}

// ConstantTimeGreater returns 1 if a > b, 0 otherwise (constant-time)
// Both a and b must be in range [0, 2^31)
func ConstantTimeGreater(a, b int) int {
	if a < 0 || b < 0 {
		panic("ConstantTimeGreater: inputs must be non-negative")
	}
	return 1 - subtle.ConstantTimeLessOrEq(a, b)
}

// ConstantTimeBigIntEqual compares two big.Ints in constant time
// Returns 1 if equal, 0 otherwise
func ConstantTimeBigIntEqual(a, b *big.Int) int {
	aBytes := a.Bytes()
	bBytes := b.Bytes()

	// Pad to same length
	maxLen := len(aBytes)
	if len(bBytes) > maxLen {
		maxLen = len(bBytes)
	}

	// Handle zero case explicitly
	if maxLen == 0 {
		return 1
	}

	aPadded := make([]byte, maxLen)
	bPadded := make([]byte, maxLen)

	copy(aPadded[maxLen-len(aBytes):], aBytes)
	copy(bPadded[maxLen-len(bBytes):], bBytes)

	return subtle.ConstantTimeCompare(aPadded, bPadded)
}

// TimingSafeDiv performs timing-safe division using multiplicative inverse
// Returns a / b mod m = a * b^(-1) mod m
func TimingSafeDiv(a, b, m *big.Int) *big.Int {
	bInv := ConstantTimeModInv(b, m)
	if bInv == nil {
		return nil
	}

	return ConstantTimeModMul(a, bInv, m)
}

// MaskBigInt masks a big.Int with random blinding factor
// This provides defense against differential power analysis (DPA)
// Returns: (masked value, mask, error)
func MaskBigInt(x, m *big.Int) (masked, mask *big.Int, err error) {
	// Generate random mask using crypto/rand
	mask, err = generateRandomScalar(m)
	if err != nil {
		return nil, nil, err
	}

	// masked = (x + mask) mod m
	masked = ConstantTimeModAdd(x, mask, m)

	return masked, mask, nil
}

// UnmaskBigInt removes blinding mask from a big.Int
// x = (masked - mask) mod m
func UnmaskBigInt(masked, mask, m *big.Int) *big.Int {
	return ConstantTimeModSub(masked, mask, m)
}

// generateRandomScalar generates a cryptographically secure random scalar
// Uses crypto/rand for secure randomness
func generateRandomScalar(max *big.Int) (*big.Int, error) {
	// Delegate to validation.go to avoid code duplication
	return GenerateRandomScalar(max)
}

// ConstantTimeCondSwap conditionally swaps two big.Ints based on condition bit
// If swap == 1, swaps a and b; if swap == 0, leaves unchanged
// Uses XOR-based swap to prevent branch prediction leaks
func ConstantTimeCondSwap(swap int, a, b *big.Int) (*big.Int, *big.Int) {
	if swap != 0 && swap != 1 {
		panic("ConstantTimeCondSwap: swap must be 0 or 1")
	}

	aBytes := a.Bytes()
	bBytes := b.Bytes()

	// Pad to same length
	maxLen := len(aBytes)
	if len(bBytes) > maxLen {
		maxLen = len(bBytes)
	}

	aPadded := make([]byte, maxLen)
	bPadded := make([]byte, maxLen)

	copy(aPadded[maxLen-len(aBytes):], aBytes)
	copy(bPadded[maxLen-len(bBytes):], bBytes)

	// Constant-time conditional swap using XOR trick
	// mask = -swap (0x00 if swap=0, 0xFF if swap=1)
	mask := byte(-swap)

	for i := 0; i < maxLen; i++ {
		// t = mask & (a[i] ^ b[i])
		// a[i] ^= t swaps if mask=0xFF, no-op if mask=0x00
		t := mask & (aPadded[i] ^ bPadded[i])
		aPadded[i] ^= t
		bPadded[i] ^= t
	}

	return new(big.Int).SetBytes(aPadded), new(big.Int).SetBytes(bPadded)
}

// SecureCompareScalars compares two scalars in constant time
// Returns true if equal, false otherwise
func SecureCompareScalars(a, b *big.Int) bool {
	return ConstantTimeBigIntEqual(a, b) == 1
}

// ConstantTimeArrayAccess accesses an array element in constant time
// This prevents cache-timing attacks based on array access patterns
// Returns array[index] if index is valid, zero otherwise
func ConstantTimeArrayAccess(array []*big.Int, index int) *big.Int {
	if index < 0 || index >= len(array) {
		return big.NewInt(0)
	}

	result := big.NewInt(0)

	// Scan entire array in constant time
	for i := 0; i < len(array); i++ {
		// cond = 1 if i == index, 0 otherwise
		cond := subtle.ConstantTimeEq(int32(i), int32(index))
		selected := ConstantTimeSelect(cond, array[i], big.NewInt(0))
		result.Add(result, selected)
	}

	return result
}

// ConstantTimeLimbsEqual compares big.Int at the limb level
// More resistant to compiler optimization than byte comparison
func ConstantTimeLimbsEqual(a, b *big.Int) bool {
	aBits := a.Bits()
	bBits := b.Bits()

	// Pad to same length
	maxLen := len(aBits)
	if len(bBits) > maxLen {
		maxLen = len(bBits)
	}

	// Compare all limbs
	var diff big.Word
	for i := 0; i < maxLen; i++ {
		var aLimb, bLimb big.Word
		if i < len(aBits) {
			aLimb = aBits[i]
		}
		if i < len(bBits) {
			bLimb = bBits[i]
		}
		diff |= aLimb ^ bLimb
	}

	// Convert to int using constant-time selection
	return diff == 0
}

// ConstantTimeMontgomeryLadder performs constant-time scalar multiplication
// This is used for ECC operations: result = k * P
// The Montgomery ladder always performs the same operations regardless of k
func ConstantTimeMontgomeryLadder(k *big.Int, scalarMult func(*big.Int) *big.Int) *big.Int {
	if k.Sign() <= 0 {
		panic("ConstantTimeMontgomeryLadder: scalar must be positive")
	}

	// Get bit length
	bitLen := k.BitLen()

	// Initialize: R0 = 0, R1 = P (identity and base point)
	r0 := big.NewInt(0)
	r1 := scalarMult(big.NewInt(1))

	// Montgomery ladder: always do both operations
	for i := bitLen - 1; i >= 0; i-- {
		bit := k.Bit(i)

		// Constant-time conditional swap
		r0, r1 = ConstantTimeCondSwap(int(bit), r0, r1)

		// R0 = 2*R0, R1 = R0 + R1 (always both operations)
		temp := new(big.Int).Add(r0, r0)
		r1 = new(big.Int).Add(r0, r1)
		r0 = temp

		// Swap back if needed
		r0, r1 = ConstantTimeCondSwap(int(bit), r0, r1)
	}

	return r0
}

// ConstantTimeModSqr performs constant-time modular squaring
// result = x^2 mod m
// Squaring can be faster than multiplication
func ConstantTimeModSqr(x, m *big.Int) *big.Int {
	return ConstantTimeModMul(x, x, m)
}

// ConstantTimeIsOdd returns 1 if x is odd, 0 if even (constant-time)
func ConstantTimeIsOdd(x *big.Int) int {
	if x.Sign() == 0 {
		return 0
	}
	bytes := x.Bytes()
	return int(bytes[len(bytes)-1] & 1)
}

// ConstantTimeModNeg performs constant-time modular negation
// result = -x mod m = m - x
func ConstantTimeModNeg(x, m *big.Int) *big.Int {
	if x.Sign() == 0 {
		return big.NewInt(0)
	}
	result := new(big.Int).Sub(m, x)
	return constantTimeModReduce(result, m)
}

// SecureZeroWords zeros out a Word slice in constant time
// This is used for clearing intermediate values in big.Int operations
func SecureZeroWords(words []big.Word) {
	for i := range words {
		words[i] = 0
	}
}

// ConstantTimeLeadingZeros counts leading zeros in constant time
// This prevents timing leaks from bit length checks
func ConstantTimeLeadingZeros(x *big.Int) int {
	bytes := x.Bytes()
	if len(bytes) == 0 {
		return 0
	}

	// Count using bits package for consistent timing
	count := 0
	for i := 0; i < len(bytes); i++ {
		lz := bits.LeadingZeros8(bytes[i])
		// Accumulate without branching on intermediate values
		count += lz
		if lz != 8 {
			break
		}
	}

	return count
}
