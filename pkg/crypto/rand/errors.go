package rand

import "errors"

var (
	// ErrInvalidLength is returned when requested length is invalid
	ErrInvalidLength = errors.New("invalid length: must be positive")

	// ErrNilMax is returned when max parameter is nil
	ErrNilMax = errors.New("max cannot be nil")

	// ErrInvalidMax is returned when max is not positive
	ErrInvalidMax = errors.New("max must be positive")

	// ErrInvalidRange is returned when range parameters are invalid
	ErrInvalidRange = errors.New("invalid range: min must be less than max")

	// ErrInvalidBitSize is returned when bit size is too small
	ErrInvalidBitSize = errors.New("bit size must be at least 2")
)
