package zk

import "errors"

var (
	// ErrNilSecret is returned when a nil secret is provided
	ErrNilSecret = errors.New("secret cannot be nil")

	// ErrNilPublicPoint is returned when a nil public point is provided
	ErrNilPublicPoint = errors.New("public point cannot be nil")

	// ErrNilCurve is returned when a nil curve is provided
	ErrNilCurve = errors.New("curve cannot be nil")

	// ErrInvalidWitness is returned when the witness doesn't satisfy the relation
	ErrInvalidWitness = errors.New("invalid witness: does not satisfy the relation")

	// ErrInvalidProof is returned when proof verification fails
	ErrInvalidProof = errors.New("invalid proof")

	// ErrMismatchedLengths is returned when array lengths don't match
	ErrMismatchedLengths = errors.New("mismatched array lengths")

	// ErrInvalidRange is returned when a value is outside valid range
	ErrInvalidRange = errors.New("value outside valid range")

	// ErrNilValue is returned when a nil value is provided
	ErrNilValue = errors.New("value cannot be nil")

	// ErrInvalidCommitment is returned when a commitment is invalid
	ErrInvalidCommitment = errors.New("invalid commitment")
)
