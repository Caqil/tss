package keygen

import "errors"

var (
	// ErrNotImplemented is returned for functionality not yet implemented
	ErrNotImplemented = errors.New("not yet implemented")

	// ErrInvalidThreshold is returned when threshold is invalid
	ErrInvalidThreshold = errors.New("invalid threshold parameters")

	// ErrInvalidPartyID is returned when party ID is invalid
	ErrInvalidPartyID = errors.New("invalid party ID")

	// ErrInvalidShare is returned when a share fails verification
	ErrInvalidShare = errors.New("share verification failed")

	// ErrInvalidCommitment is returned when a commitment is invalid
	ErrInvalidCommitment = errors.New("invalid commitment")

	// ErrMissingData is returned when required protocol data is missing
	ErrMissingData = errors.New("missing required protocol data")

	// ErrProtocolAbort is returned when the protocol must abort
	ErrProtocolAbort = errors.New("protocol aborted due to verification failure")

	// ErrNilSecret is returned when a nil secret is provided
	ErrNilSecret = errors.New("secret cannot be nil")

	// ErrNilCurve is returned when a nil curve is provided
	ErrNilCurve = errors.New("curve cannot be nil")

	// ErrInsufficientShares is returned when not enough shares for reconstruction
	ErrInsufficientShares = errors.New("insufficient shares for reconstruction")

	// ErrMissingRound1Data is returned when Round 1 data is missing
	ErrMissingRound1Data = errors.New("missing Round 1 data from some parties")

	// ErrMissingRound2Data is returned when Round 2 data is missing
	ErrMissingRound2Data = errors.New("missing Round 2 data from some parties")

	// ErrMissingShare is returned when expected share is missing
	ErrMissingShare = errors.New("missing expected share")

	// ErrMissingCommitments is returned when commitments are missing
	ErrMissingCommitments = errors.New("missing commitments from party")

	// ErrShareVerificationFailed is returned when share verification fails
	ErrShareVerificationFailed = errors.New("share failed Feldman VSS verification")
)
