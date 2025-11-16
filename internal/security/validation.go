package security

import (
	cryptoRand "crypto/rand"
	"errors"
	"math/big"
)

var (
	// ErrInvalidThreshold is returned when threshold parameters are invalid
	ErrInvalidThreshold = errors.New("invalid threshold: must satisfy 1 <= t <= n")

	// ErrInvalidPartyID is returned when party ID is out of range
	ErrInvalidPartyID = errors.New("invalid party ID: must be in range [0, n)")

	// ErrInvalidPartyCount is returned when party count is too small
	ErrInvalidPartyCount = errors.New("invalid party count: must be >= 2")

	// ErrInvalidRange is returned when a value is outside expected range
	ErrInvalidRange = errors.New("value out of valid range")
)

// ValidateThreshold checks if threshold parameters are valid
// Returns error if:
// - threshold < 1
// - threshold > parties
// - parties < 2
func ValidateThreshold(threshold, parties int) error {
	if parties < 2 {
		return ErrInvalidPartyCount
	}

	if threshold < 1 || threshold > parties {
		return ErrInvalidThreshold
	}

	return nil
}

// ValidatePartyID checks if party ID is valid for given party count
func ValidatePartyID(partyID, parties int) error {
	if parties < 2 {
		return ErrInvalidPartyCount
	}

	if partyID < 0 || partyID >= parties {
		return ErrInvalidPartyID
	}

	return nil
}

// ValidateScalarInRange checks if scalar is in valid range [1, max)
func ValidateScalarInRange(value, max *big.Int) error {
	if value == nil || max == nil {
		return errors.New("nil value provided")
	}

	if value.Sign() <= 0 {
		return errors.New("scalar must be positive")
	}

	if value.Cmp(max) >= 0 {
		return ErrInvalidRange
	}

	return nil
}

// ValidateNonZeroScalar checks if scalar is non-zero
func ValidateNonZeroScalar(value *big.Int) error {
	if value == nil {
		return errors.New("nil scalar")
	}

	if value.Sign() == 0 {
		return errors.New("scalar is zero")
	}

	return nil
}

// SanitizeInput validates and sanitizes string input
// Returns error if input contains null bytes or exceeds max length
func SanitizeInput(input string, maxLength int) error {
	if len(input) > maxLength {
		return errors.New("input exceeds maximum length")
	}

	// Check for null bytes
	for i := 0; i < len(input); i++ {
		if input[i] == 0 {
			return errors.New("input contains null bytes")
		}
	}

	return nil
}

// GenerateRandomScalar generates a cryptographically secure random scalar
// in range [1, max). This is a wrapper around pkg/crypto/rand for convenience
func GenerateRandomScalar(max *big.Int) (*big.Int, error) {
	// Import needed - will be resolved at compile time
	// This delegates to the crypto/rand package
	return generateRandomScalarInternal(max)
}

// generateRandomScalarInternal is the internal implementation
// This avoids circular imports by implementing directly
func generateRandomScalarInternal(max *big.Int) (*big.Int, error) {
	if max == nil || max.Sign() <= 0 {
		return nil, errors.New("max must be positive")
	}

	// Use crypto/rand from standard library directly
	// to avoid circular dependency
	value, err := cryptoRand.Int(cryptoRand.Reader, max)
	if err != nil {
		return nil, err
	}

	// Ensure non-zero
	for value.Sign() == 0 {
		value, err = cryptoRand.Int(cryptoRand.Reader, max)
		if err != nil {
			return nil, err
		}
	}

	return value, nil
}
