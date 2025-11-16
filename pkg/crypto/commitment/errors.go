package commitment

import "errors"

var (
	// ErrNilCurve is returned when a nil curve is provided
	ErrNilCurve = errors.New("curve cannot be nil")

	// ErrNilValue is returned when a nil value is provided
	ErrNilValue = errors.New("value cannot be nil")

	// ErrNilScalar is returned when a nil scalar is provided
	ErrNilScalar = errors.New("scalar cannot be nil")

	// ErrEmptyValue is returned when an empty value is provided
	ErrEmptyValue = errors.New("value cannot be empty")

	// ErrEmptyValues is returned when an empty values slice is provided
	ErrEmptyValues = errors.New("values cannot be empty")

	// ErrNilCommitment is returned when a nil commitment is provided
	ErrNilCommitment = errors.New("commitment cannot be nil")

	// ErrCurveMismatch is returned when commitments use different curves
	ErrCurveMismatch = errors.New("commitments must use the same curve")

	// ErrInvalidOpening is returned when commitment opening verification fails
	ErrInvalidOpening = errors.New("commitment opening verification failed")

	// ErrInvalidCommitment is returned when a commitment is invalid
	ErrInvalidCommitment = errors.New("invalid commitment")
)
