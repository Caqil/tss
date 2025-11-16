package network

import "errors"

var (
	// ErrInvalidPartyID is returned when party ID is invalid
	ErrInvalidPartyID = errors.New("invalid party ID")

	// ErrInvalidPartyCount is returned when party count is invalid
	ErrInvalidPartyCount = errors.New("invalid party count")

	// ErrInvalidConfig is returned when configuration is invalid
	ErrInvalidConfig = errors.New("invalid configuration")

	// ErrInvalidPeerAddrs is returned when peer addresses are invalid
	ErrInvalidPeerAddrs = errors.New("invalid peer addresses")

	// ErrInvalidListenAddr is returned when listen address is invalid
	ErrInvalidListenAddr = errors.New("invalid listen address")

	// ErrInvalidPeerAddr is returned when a peer address is invalid
	ErrInvalidPeerAddr = errors.New("invalid peer address")

	// ErrSelfConnection is returned when trying to connect to self
	ErrSelfConnection = errors.New("cannot connect to self")

	// ErrNotConnected is returned when peer is not connected
	ErrNotConnected = errors.New("peer not connected")

	// ErrAlreadyConnected is returned when peer is already connected
	ErrAlreadyConnected = errors.New("peer already connected")

	// ErrConnectionFailed is returned when connection fails
	ErrConnectionFailed = errors.New("connection failed")

	// ErrSendFailed is returned when message send fails
	ErrSendFailed = errors.New("failed to send message")

	// ErrReceiveFailed is returned when message receive fails
	ErrReceiveFailed = errors.New("failed to receive message")

	// ErrMessageTooLarge is returned when message exceeds size limit
	ErrMessageTooLarge = errors.New("message too large")

	// ErrInvalidMessage is returned when message is malformed
	ErrInvalidMessage = errors.New("invalid message")

	// ErrInvalidMAC is returned when MAC verification fails
	ErrInvalidMAC = errors.New("invalid message authentication code")

	// ErrTimeout is returned when operation times out
	ErrTimeout = errors.New("operation timeout")

	// ErrRateLimited is returned when rate limit is exceeded
	ErrRateLimited = errors.New("rate limit exceeded")

	// ErrHandlerNotFound is returned when no handler is registered
	ErrHandlerNotFound = errors.New("handler not found for message type")

	// ErrHandlerAlreadyRegistered is returned when handler already exists
	ErrHandlerAlreadyRegistered = errors.New("handler already registered")

	// ErrSessionNotFound is returned when session doesn't exist
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionExpired is returned when session has expired
	ErrSessionExpired = errors.New("session expired")

	// ErrEncryptionFailed is returned when encryption fails
	ErrEncryptionFailed = errors.New("encryption failed")

	// ErrDecryptionFailed is returned when decryption fails
	ErrDecryptionFailed = errors.New("decryption failed")

	// ErrInvalidNonce is returned when nonce is invalid or reused
	ErrInvalidNonce = errors.New("invalid or reused nonce")

	// ErrInvalidSequence is returned when sequence number is invalid
	ErrInvalidSequence = errors.New("invalid sequence number")

	// ErrReplayAttack is returned when replay attack is detected
	ErrReplayAttack = errors.New("replay attack detected")

	// ErrTransportClosed is returned when transport is closed
	ErrTransportClosed = errors.New("transport closed")

	// ErrShutdown is returned when shutting down
	ErrShutdown = errors.New("shutting down")

	// ErrPeerTimeout is returned when peer doesn't respond
	ErrPeerTimeout = errors.New("peer timeout")

	// ErrTLSHandshakeFailed is returned when TLS handshake fails
	ErrTLSHandshakeFailed = errors.New("TLS handshake failed")

	// ErrInvalidCertificate is returned when certificate is invalid
	ErrInvalidCertificate = errors.New("invalid certificate")

	// ErrBufferFull is returned when message buffer is full
	ErrBufferFull = errors.New("message buffer full")
)
