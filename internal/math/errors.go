package math

import "errors"

var (
	// ErrEmptyCoefficients is returned when coefficients slice is empty
	ErrEmptyCoefficients = errors.New("coefficients cannot be empty")

	// ErrInvalidModulus is returned when modulus is invalid
	ErrInvalidModulus = errors.New("modulus must be positive")

	// ErrInvalidDegree is returned when degree is negative
	ErrInvalidDegree = errors.New("degree must be non-negative")

	// ErrNilPolynomial is returned when a nil polynomial is provided
	ErrNilPolynomial = errors.New("polynomial cannot be nil")

	// ErrNilScalar is returned when a nil scalar is provided
	ErrNilScalar = errors.New("scalar cannot be nil")

	// ErrModulusMismatch is returned when polynomials have different moduli
	ErrModulusMismatch = errors.New("polynomials must have the same modulus")

	// ErrPointValueMismatch is returned when points and values have different lengths
	ErrPointValueMismatch = errors.New("points and values must have the same length")

	// ErrEmptyPoints is returned when points slice is empty
	ErrEmptyPoints = errors.New("points cannot be empty")

	// ErrDuplicatePoints is returned when interpolation points are not unique
	ErrDuplicatePoints = errors.New("interpolation points must be unique")

	// ErrNilSecret is returned when a nil secret is provided
	ErrNilSecret = errors.New("secret cannot be nil")

	// ErrInsufficientShares is returned when not enough shares for reconstruction
	ErrInsufficientShares = errors.New("insufficient shares for reconstruction")

	// ErrTooManyShares is returned when too many shares are provided
	ErrTooManyShares = errors.New("too many shares provided")

	// ErrNilShare is returned when a nil share is provided
	ErrNilShare = errors.New("share cannot be nil")

	// ErrNilPoint is returned when a nil point is provided
	ErrNilPoint = errors.New("point cannot be nil")

	// ErrInvalidShare is returned when a share is invalid
	ErrInvalidShare = errors.New("invalid share")

	// ErrShareIndexMismatch is returned when share indices don't match
	ErrShareIndexMismatch = errors.New("share indices must match")
)
