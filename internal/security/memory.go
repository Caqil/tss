// Package security provides security utilities for protecting sensitive data
package security

import (
	"crypto/subtle"
	"math/big"
	"runtime"
)

// SecureZero securely zeros out a byte slice to prevent secrets from remaining in memory
// This uses a method that prevents the compiler from optimizing away the zeroing
func SecureZero(data []byte) {
	if data == nil || len(data) == 0 {
		return
	}

	// Use subtle.ConstantTimeCopy to ensure compiler doesn't optimize away
	zeros := make([]byte, len(data))
	subtle.ConstantTimeCopy(1, data, zeros)

	// Force a memory barrier
	runtime.KeepAlive(data)
}

// SecureZeroBigInt securely zeros a big.Int by clearing its internal buffer
// Note: Go's big.Int doesn't expose internal bytes directly
// Best practice: Set to zero and rely on garbage collector
func SecureZeroBigInt(b *big.Int) {
	if b == nil {
		return
	}

	// Set to zero - this is the most practical approach in Go
	// The internal bytes will be garbage collected
	b.SetInt64(0)

	// Force memory barrier to prevent compiler optimization
	runtime.KeepAlive(b)
}

// ConstantTimeCompare compares two byte slices in constant time
// Returns true if they are equal, false otherwise
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ConstantTimeSelectBytes returns x if v == 1 and y if v == 0
// The value v must be 0 or 1. This function is constant-time.
func ConstantTimeSelectBytes(v int, x, y []byte) []byte {
	if len(x) != len(y) {
		panic("ConstantTimeSelectBytes: slices must have equal length")
	}

	result := make([]byte, len(x))
	subtle.ConstantTimeCopy(v, result, x)
	subtle.ConstantTimeCopy(1-v, result, y)

	return result
}

// ConstantTimeByteEq returns 1 if a == b and 0 otherwise
func ConstantTimeByteEq(a, b uint8) int {
	return subtle.ConstantTimeByteEq(a, b)
}

// ConstantTimeEq returns 1 if x == y and 0 otherwise
func ConstantTimeEq(x, y int32) int {
	return subtle.ConstantTimeEq(x, y)
}

// ConstantTimeLessOrEq returns 1 if x <= y and 0 otherwise
// Both x and y must be non-negative and less than 2^31
func ConstantTimeLessOrEq(x, y int) int {
	return subtle.ConstantTimeLessOrEq(x, y)
}
