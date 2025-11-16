package hash

import "errors"

var (
	// ErrNilCurve is returned when a nil curve is provided
	ErrNilCurve = errors.New("curve cannot be nil")

	// ErrInvalidLength is returned when an invalid length is specified
	ErrInvalidLength = errors.New("length must be positive")

	// ErrInvalidHash is returned when hash verification fails
	ErrInvalidHash = errors.New("hash verification failed")

	// ErrHashToCurveFailed is returned when hash-to-curve fails
	ErrHashToCurveFailed = errors.New("hash-to-curve failed to find valid point")
)
