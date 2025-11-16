// Package network provides secure P2P networking for MPC-TSS protocols
package network

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// MessageType identifies the type of message being sent
type MessageType uint8

const (
	// MessageTypeDKGRound1 is for DKG round 1 messages
	MessageTypeDKGRound1 MessageType = iota
	// MessageTypeDKGRound2 is for DKG round 2 messages
	MessageTypeDKGRound2
	// MessageTypeDKGRound3 is for DKG round 3 messages
	MessageTypeDKGRound3
	// MessageTypeSignRound1 is for signing round 1 messages
	MessageTypeSignRound1
	// MessageTypeSignRound2 is for signing round 2 messages
	MessageTypeSignRound2
	// MessageTypeSignRound3 is for signing round 3 messages
	MessageTypeSignRound3
	// MessageTypeSignRound4 is for signing round 4 messages
	MessageTypeSignRound4
	// MessageTypePreSignRound1 is for presigning round 1 messages
	MessageTypePreSignRound1
	// MessageTypePreSignRound2 is for presigning round 2 messages
	MessageTypePreSignRound2
	// MessageTypeHeartbeat is for keepalive messages
	MessageTypeHeartbeat
	// MessageTypeAck is for acknowledgments
	MessageTypeAck
	// MessageTypeError is for error notifications
	MessageTypeError
)

// Message represents a network message
type Message struct {
	// Type identifies the message type
	Type MessageType

	// From is the sender party ID
	From int

	// To is the recipient party ID (-1 for broadcast)
	To int

	// SessionID uniquely identifies the protocol session
	SessionID []byte

	// Payload is the encrypted message payload
	Payload []byte

	// MAC is the message authentication code
	MAC []byte

	// Timestamp is when the message was created
	Timestamp time.Time

	// Nonce is a unique nonce for this message
	Nonce []byte

	// Sequence number for ordering
	Sequence uint64
}

// Transport defines the interface for network transport
type Transport interface {
	// Start initializes and starts the transport
	Start(ctx context.Context) error

	// Stop gracefully shuts down the transport
	Stop(ctx context.Context) error

	// Send sends a message to a specific party
	Send(ctx context.Context, partyID int, msg *Message) error

	// Broadcast sends a message to all parties
	Broadcast(ctx context.Context, msg *Message) error

	// Receive receives a message from any party
	Receive(ctx context.Context) (*Message, error)

	// LocalPartyID returns this party's ID
	LocalPartyID() int

	// PeerCount returns the number of connected peers
	PeerCount() int

	// IsConnected checks if a specific party is connected
	IsConnected(partyID int) bool
}

// P2PNetwork provides peer-to-peer networking functionality
type P2PNetwork interface {
	Transport

	// RegisterHandler registers a handler for a specific message type
	RegisterHandler(msgType MessageType, handler HandlerFunc) error

	// UnregisterHandler removes a handler for a message type
	UnregisterHandler(msgType MessageType) error

	// SetRateLimit sets the rate limit for a specific party
	SetRateLimit(partyID int, messagesPerSecond int) error

	// GetPeerInfo returns information about a peer
	GetPeerInfo(partyID int) (*PeerInfo, error)

	// GetMetrics returns network metrics
	GetMetrics() *NetworkMetrics
}

// HandlerFunc is called when a message of a specific type is received
type HandlerFunc func(ctx context.Context, msg *Message) error

// PeerInfo contains information about a connected peer
type PeerInfo struct {
	PartyID      int
	Address      string
	Connected    bool
	LastSeen     time.Time
	MessagesSent uint64
	MessagesRecv uint64
	BytesSent    uint64
	BytesRecv    uint64
	Latency      time.Duration
	TLSVersion   uint16
	CipherSuite  uint16
}

// NetworkMetrics contains network performance metrics
type NetworkMetrics struct {
	// Total messages sent/received
	MessagesSent     uint64
	MessagesReceived uint64

	// Total bytes sent/received
	BytesSent     uint64
	BytesReceived uint64

	// Connection metrics
	ActiveConnections int
	TotalConnections  uint64
	FailedConnections uint64

	// Error counters
	SendErrors    uint64
	ReceiveErrors uint64
	TimeoutErrors uint64

	// Rate limiting
	RateLimitedMessages uint64

	// Latency statistics
	AverageLatency time.Duration
	MinLatency     time.Duration
	MaxLatency     time.Duration

	// Uptime
	Uptime time.Duration
}

// TransportConfig configures the network transport
type TransportConfig struct {
	// PartyID is this party's identifier
	PartyID int

	// TotalParties is the total number of parties
	TotalParties int

	// ListenAddr is the address to listen on
	ListenAddr string

	// PeerAddrs maps party IDs to their addresses
	PeerAddrs map[int]string

	// TLSConfig for secure connections
	TLSConfig *tls.Config

	// MaxMessageSize limits message size (default: 10MB)
	MaxMessageSize int

	// SendTimeout for send operations
	SendTimeout time.Duration

	// ReceiveTimeout for receive operations
	ReceiveTimeout time.Duration

	// ReconnectInterval for automatic reconnection
	ReconnectInterval time.Duration

	// MaxReconnectAttempts before giving up
	MaxReconnectAttempts int

	// EnableRateLimiting enables rate limiting
	EnableRateLimiting bool

	// DefaultRateLimit is messages per second per peer
	DefaultRateLimit int

	// BufferSize for message queues
	BufferSize int

	// EnableMetrics enables metrics collection
	EnableMetrics bool

	// EnableAuditLog enables audit logging
	EnableAuditLog bool

	// AuditLogPath is the path for audit logs
	AuditLogPath string
}

// DefaultTransportConfig returns a secure default configuration
func DefaultTransportConfig(partyID, totalParties int) *TransportConfig {
	return &TransportConfig{
		PartyID:              partyID,
		TotalParties:         totalParties,
		MaxMessageSize:       10 * 1024 * 1024, // 10MB
		SendTimeout:          30 * time.Second,
		ReceiveTimeout:       30 * time.Second,
		ReconnectInterval:    5 * time.Second,
		MaxReconnectAttempts: 10,
		EnableRateLimiting:   true,
		DefaultRateLimit:     100, // 100 messages/second
		BufferSize:           1000,
		EnableMetrics:        true,
		EnableAuditLog:       true,
		PeerAddrs:            make(map[int]string),
	}
}

// Validate validates the transport configuration
func (c *TransportConfig) Validate() error {
	if c.PartyID < 0 || c.PartyID >= c.TotalParties {
		return ErrInvalidPartyID
	}

	if c.TotalParties < 2 {
		return ErrInvalidPartyCount
	}

	if c.MaxMessageSize <= 0 {
		return ErrInvalidConfig
	}

	if c.SendTimeout <= 0 {
		return ErrInvalidConfig
	}

	if c.ReceiveTimeout <= 0 {
		return ErrInvalidConfig
	}

	if c.BufferSize <= 0 {
		return ErrInvalidConfig
	}

	if len(c.PeerAddrs) != c.TotalParties-1 {
		return ErrInvalidPeerAddrs
	}

	// Validate listen address if provided
	if c.ListenAddr != "" {
		_, _, err := net.SplitHostPort(c.ListenAddr)
		if err != nil {
			return ErrInvalidListenAddr
		}
	}

	// Validate peer addresses
	for partyID, addr := range c.PeerAddrs {
		if partyID == c.PartyID {
			return ErrSelfConnection
		}

		if partyID < 0 || partyID >= c.TotalParties {
			return ErrInvalidPartyID
		}

		_, _, err := net.SplitHostPort(addr)
		if err != nil {
			return ErrInvalidPeerAddr
		}
	}

	return nil
}

// Session represents a network session with security context
type Session struct {
	// SessionID uniquely identifies this session
	SessionID []byte

	// PartyID is the remote party's ID
	PartyID int

	// LocalPartyID is this party's ID
	LocalPartyID int

	// SharedSecret for authenticated encryption
	SharedSecret []byte

	// Created timestamp
	Created time.Time

	// LastActivity timestamp
	LastActivity time.Time

	// Sequence number for message ordering
	SendSequence uint64
	RecvSequence uint64

	// Connection state
	Conn net.Conn

	// TLS connection state
	TLSState *tls.ConnectionState
}

// MessageHandler processes incoming messages
type MessageHandler interface {
	// HandleMessage processes a received message
	HandleMessage(ctx context.Context, msg *Message) error

	// HandleError processes errors
	HandleError(ctx context.Context, err error, msg *Message)
}

// ConnectionManager manages peer connections
type ConnectionManager interface {
	// Connect establishes a connection to a peer
	Connect(ctx context.Context, partyID int, addr string) error

	// Disconnect closes a connection to a peer
	Disconnect(ctx context.Context, partyID int) error

	// GetConnection returns the connection for a party
	GetConnection(partyID int) (net.Conn, error)

	// IsConnected checks if connected to a party
	IsConnected(partyID int) bool

	// ConnectedPeers returns list of connected party IDs
	ConnectedPeers() []int

	// WaitForPeers waits for a minimum number of peers
	WaitForPeers(ctx context.Context, minPeers int) error
}

// SecureChannel provides encrypted and authenticated communication
type SecureChannel interface {
	// Encrypt encrypts and authenticates a message
	Encrypt(plaintext []byte) (ciphertext []byte, err error)

	// Decrypt decrypts and verifies a message
	Decrypt(ciphertext []byte) (plaintext []byte, err error)

	// RotateKeys rotates encryption keys
	RotateKeys() error
}
