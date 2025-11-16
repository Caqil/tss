package signing

import "errors"

var (
	// ErrInvalidKeyShare is returned when the key share is invalid
	ErrInvalidKeyShare = errors.New("invalid key share")

	// ErrInvalidMessage is returned when the message hash is invalid
	ErrInvalidMessage = errors.New("invalid message hash")

	// ErrInvalidSignature is returned when signature verification fails
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrInsufficientParties is returned when not enough parties participate
	ErrInsufficientParties = errors.New("insufficient parties for threshold")

	// ErrProtocolAbort is returned when the signing protocol must abort
	ErrProtocolAbort = errors.New("signing protocol aborted")

	// ErrInvalidNonce is returned when a nonce is invalid
	ErrInvalidNonce = errors.New("invalid nonce")

	// ErrInvalidCommitment is returned when a commitment is invalid
	ErrInvalidCommitment = errors.New("invalid commitment")

	// ErrDuplicateParty is returned when a party ID appears twice
	ErrDuplicateParty = errors.New("duplicate party ID")

	// ErrInvalidPartyID is returned when a party ID is invalid
	ErrInvalidPartyID = errors.New("invalid party ID")

	// ErrMissingRound1Data is returned when Round 1 data is missing
	ErrMissingRound1Data = errors.New("missing round 1 data")

	// ErrMissingRound2Data is returned when Round 2 data is missing
	ErrMissingRound2Data = errors.New("missing round 2 data")

	// ErrMissingRound3Data is returned when Round 3 data is missing
	ErrMissingRound3Data = errors.New("missing round 3 data")

	// ErrCommitmentMismatch is returned when commitment verification fails
	ErrCommitmentMismatch = errors.New("commitment does not match revealed value")

	// ErrInvalidProof is returned when a zero-knowledge proof is invalid
	ErrInvalidProof = errors.New("invalid zero-knowledge proof")

	// ErrSessionTimeout is returned when a signing session times out
	ErrSessionTimeout = errors.New("signing session timeout")

	// ErrSessionExpired is returned when a session has expired
	ErrSessionExpired = errors.New("signing session expired")

	// ErrReplayAttack is returned when a replay attack is detected
	ErrReplayAttack = errors.New("replay attack detected")

	// ErrInvalidSessionID is returned when session ID is invalid
	ErrInvalidSessionID = errors.New("invalid session ID")

	// ErrNilCurve is returned when curve is nil
	ErrNilCurve = errors.New("curve cannot be nil")

	// ErrInvalidR is returned when R value is invalid
	ErrInvalidR = errors.New("invalid R value")

	// ErrInvalidS is returned when S value is invalid
	ErrInvalidS = errors.New("invalid S value")

	// ErrMaliciousParty is returned when malicious behavior is detected
	ErrMaliciousParty = errors.New("malicious party detected")

	// ErrInvalidPreSignature is returned when pre-signature is invalid
	ErrInvalidPreSignature = errors.New("invalid pre-signature")

	// ErrPreSignatureAlreadyUsed is returned when trying to reuse a pre-signature
	ErrPreSignatureAlreadyUsed = errors.New("pre-signature already used")
)
