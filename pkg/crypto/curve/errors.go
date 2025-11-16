package curve

import "errors"

var (
	// ErrUnsupportedCurve is returned when an unsupported curve is requested
	ErrUnsupportedCurve = errors.New("unsupported curve type")

	// ErrInvalidPoint is returned when a point is not on the curve
	ErrInvalidPoint = errors.New("invalid point: not on curve")

	// ErrInvalidScalar is returned when a scalar is invalid (e.g., zero or >= order)
	ErrInvalidScalar = errors.New("invalid scalar value")

	// ErrPointAtInfinity is returned when operating on the point at infinity
	ErrPointAtInfinity = errors.New("point at infinity")

	// ErrInvalidEncoding is returned when unmarshaling fails
	ErrInvalidEncoding = errors.New("invalid point encoding")

	// ErrScalarZero is returned when a scalar is zero but shouldn't be
	ErrScalarZero = errors.New("scalar is zero")

	// ErrInvalidCurve is returned when curve parameters are invalid
	ErrInvalidCurve = errors.New("invalid curve parameters")
)
