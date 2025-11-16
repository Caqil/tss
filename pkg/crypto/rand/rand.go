// Package rand provides cryptographically secure random number generation
package rand

import (
	"crypto/rand"
	"io"
	"math/big"
)

// Reader is the default cryptographically secure random number generator
var Reader io.Reader = rand.Reader

// GenerateRandomBytes generates n cryptographically secure random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, ErrInvalidLength
	}

	bytes := make([]byte, n)
	if _, err := io.ReadFull(Reader, bytes); err != nil {
		return nil, err
	}

	return bytes, nil
}

// GenerateRandomScalar generates a random scalar in range [1, max)
// This is cryptographically secure and uniform
func GenerateRandomScalar(max *big.Int) (*big.Int, error) {
	if max == nil {
		return nil, ErrNilMax
	}

	if max.Sign() <= 0 {
		return nil, ErrInvalidMax
	}

	// Generate random number in range [0, max)
	value, err := rand.Int(Reader, max)
	if err != nil {
		return nil, err
	}

	// Ensure non-zero by regenerating if zero
	// This is still uniform because we're rejecting with probability 1/max
	for value.Sign() == 0 {
		value, err = rand.Int(Reader, max)
		if err != nil {
			return nil, err
		}
	}

	return value, nil
}

// GenerateRandomInt generates a random integer in range [min, max)
func GenerateRandomInt(min, max int) (int, error) {
	if min >= max {
		return 0, ErrInvalidRange
	}

	diff := max - min
	n, err := rand.Int(Reader, big.NewInt(int64(diff)))
	if err != nil {
		return 0, err
	}

	return int(n.Int64()) + min, nil
}

// GenerateNonce generates a cryptographically secure nonce of specified length
func GenerateNonce(length int) ([]byte, error) {
	return GenerateRandomBytes(length)
}

// GenerateRandomPrime generates a random prime of the specified bit size
func GenerateRandomPrime(bits int) (*big.Int, error) {
	if bits < 2 {
		return nil, ErrInvalidBitSize
	}

	prime, err := rand.Prime(Reader, bits)
	if err != nil {
		return nil, err
	}

	return prime, nil
}

// Shuffle performs a cryptographically secure Fisher-Yates shuffle
func Shuffle(n int, swap func(i, j int)) error {
	if n < 0 {
		return ErrInvalidLength
	}

	for i := n - 1; i > 0; i-- {
		j, err := GenerateRandomInt(0, i+1)
		if err != nil {
			return err
		}
		swap(i, j)
	}

	return nil
}
