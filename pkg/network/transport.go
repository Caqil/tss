// Package network - TLS-based P2P transport implementation
package network

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// TLSTransport implements secure P2P transport using TLS 1.3
type TLSTransport struct {
	config *TransportConfig

	// Connection management
	listener    net.Listener
	connections map[int]*peerConnection
	connMu      sync.RWMutex

	// Message handlers
	handlers   map[MessageType]HandlerFunc
	handlersMu sync.RWMutex

	// Channels
	inbound  chan *Message
	outbound chan *outboundMessage

	// Metrics
	metrics   *NetworkMetrics
	startTime time.Time

	// Rate limiting
	rateLimiters map[int]*rateLimiter
	rateLimitMu  sync.RWMutex

	// Encryption
	channels   map[int]*AESGCMChannel
	channelsMu sync.RWMutex

	// State
	running atomic.Bool
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc

	// Audit logging
	auditLogger *AuditLogger
}

// peerConnection represents a connection to a peer
type peerConnection struct {
	partyID  int
	conn     net.Conn
	tlsConn  *tls.Conn
	tlsState *tls.ConnectionState
	session  *Session
	lastSeen time.Time
	sendSeq  uint64
	recvSeq  uint64
	mu       sync.RWMutex
}

// outboundMessage is a message queued for sending
type outboundMessage struct {
	partyID int
	message *Message
	errChan chan error
}

// NewTLSTransport creates a new TLS transport
func NewTLSTransport(config *TransportConfig) (*TLSTransport, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	transport := &TLSTransport{
		config:       config,
		connections:  make(map[int]*peerConnection),
		handlers:     make(map[MessageType]HandlerFunc),
		inbound:      make(chan *Message, config.BufferSize),
		outbound:     make(chan *outboundMessage, config.BufferSize),
		rateLimiters: make(map[int]*rateLimiter),
		channels:     make(map[int]*AESGCMChannel),
		ctx:          ctx,
		cancel:       cancel,
		metrics: &NetworkMetrics{
			MinLatency: time.Hour, // Will be updated
		},
		startTime: time.Now(),
	}

	// Initialize rate limiters
	if config.EnableRateLimiting {
		for partyID := range config.PeerAddrs {
			transport.rateLimiters[partyID] = newRateLimiter(config.DefaultRateLimit)
		}
	}

	// Initialize audit logger
	if config.EnableAuditLog {
		logger, err := NewAuditLogger(config.AuditLogPath)
		if err != nil {
			cancel()
			return nil, err
		}
		transport.auditLogger = logger
	}

	return transport, nil
}

// Start starts the transport
func (t *TLSTransport) Start(ctx context.Context) error {
	if !t.running.CompareAndSwap(false, true) {
		return ErrAlreadyConnected
	}

	// Start listener
	if err := t.startListener(); err != nil {
		t.running.Store(false)
		return err
	}

	// Start worker goroutines
	t.wg.Add(3)
	go t.acceptLoop()
	go t.sendLoop()
	go t.receiveLoop()

	// Connect to peers
	for partyID, addr := range t.config.PeerAddrs {
		if partyID < t.config.PartyID {
			// Only connect to lower-ID peers (higher-ID peers will connect to us)
			go t.connectToPeer(partyID, addr)
		}
	}

	return nil
}

// startListener starts the TLS listener
func (t *TLSTransport) startListener() error {
	listener, err := tls.Listen("tcp", t.config.ListenAddr, t.config.TLSConfig)
	if err != nil {
		return ErrConnectionFailed
	}

	t.listener = listener
	return nil
}

// acceptLoop accepts incoming connections
func (t *TLSTransport) acceptLoop() {
	defer t.wg.Done()

	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		// Set deadline to allow periodic context checking
		if dl, ok := t.ctx.Deadline(); ok {
			t.listener.(*net.TCPListener).SetDeadline(dl)
		} else {
			t.listener.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := t.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if !t.running.Load() {
				return
			}
			atomic.AddUint64(&t.metrics.FailedConnections, 1)
			continue
		}

		// Handle connection in goroutine
		go t.handleIncomingConnection(conn)
	}
}

// handleIncomingConnection handles a new incoming connection
func (t *TLSTransport) handleIncomingConnection(conn net.Conn) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return
	}

	// Perform TLS handshake with timeout
	if err := tlsConn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		conn.Close()
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		atomic.AddUint64(&t.metrics.FailedConnections, 1)
		if t.auditLogger != nil {
			t.auditLogger.LogConnectionFailed(t.config.PartyID, -1, err)
		}
		return
	}

	// Clear deadline
	tlsConn.SetDeadline(time.Time{})

	// Get connection state
	state := tlsConn.ConnectionState()

	// Extract party ID from certificate CN or SAN
	if len(state.PeerCertificates) == 0 {
		conn.Close()
		atomic.AddUint64(&t.metrics.FailedConnections, 1)
		if t.auditLogger != nil {
			t.auditLogger.LogAuthenticationFailure(t.config.PartyID, -1, "no peer certificates")
		}
		return
	}

	// Extract party ID from certificate subject common name
	// Format expected: "mpc-tss-party-N" where N is the party ID
	cert := state.PeerCertificates[0]
	partyID := extractPartyIDFromCertificate(cert)

	if partyID < 0 || partyID >= t.config.TotalParties {
		conn.Close()
		atomic.AddUint64(&t.metrics.FailedConnections, 1)
		if t.auditLogger != nil {
			t.auditLogger.LogAuthenticationFailure(t.config.PartyID, partyID, "invalid party ID in certificate")
		}
		return
	}

	// Prevent self-connection
	if partyID == t.config.PartyID {
		conn.Close()
		return
	}

	// Check if already connected
	t.connMu.RLock()
	existing, exists := t.connections[partyID]
	t.connMu.RUnlock()

	if exists && existing != nil {
		// Already connected, close new connection
		conn.Close()
		return
	}

	// Generate cryptographically secure session ID
	sessionID, err := generateSecureSessionID()
	if err != nil {
		conn.Close()
		atomic.AddUint64(&t.metrics.FailedConnections, 1)
		return
	}

	// Create session
	session := &Session{
		SessionID:    sessionID,
		PartyID:      partyID,
		LocalPartyID: t.config.PartyID,
		Created:      time.Now(),
		LastActivity: time.Now(),
		Conn:         conn,
		TLSState:     &state,
	}

	// Create peer connection
	peerConn := &peerConnection{
		partyID:  partyID,
		conn:     conn,
		tlsConn:  tlsConn,
		tlsState: &state,
		session:  session,
		lastSeen: time.Now(),
	}

	// Store connection
	t.connMu.Lock()
	t.connections[partyID] = peerConn
	t.connMu.Unlock()

	// Initialize encryption channel
	sharedSecret, err := GenerateSharedSecret()
	if err != nil {
		conn.Close()
		return
	}

	sessionKey, err := DeriveSessionKey(sharedSecret, sessionID)
	if err != nil {
		conn.Close()
		return
	}

	channel, err := NewAESGCMChannel(sessionKey)
	if err != nil {
		conn.Close()
		return
	}

	t.channelsMu.Lock()
	t.channels[partyID] = channel
	t.channelsMu.Unlock()

	atomic.AddUint64(&t.metrics.TotalConnections, 1)
	t.metrics.ActiveConnections++

	// Log successful connection
	if t.auditLogger != nil {
		t.auditLogger.LogConnectionEstablished(t.config.PartyID, partyID, state.Version)
	}
}

// extractPartyIDFromCertificate extracts party ID from certificate
// Expected CN format: "mpc-tss-party-N" where N is the party ID
func extractPartyIDFromCertificate(cert *x509.Certificate) int {
	// Try to extract from CommonName
	cn := cert.Subject.CommonName

	// Expected format: "mpc-tss-party-N"
	var partyID int
	if _, err := fmt.Sscanf(cn, "mpc-tss-party-%d", &partyID); err == nil {
		return partyID
	}

	// Try to extract from DNS names in SAN
	for _, name := range cert.DNSNames {
		if _, err := fmt.Sscanf(name, "party-%d", &partyID); err == nil {
			return partyID
		}
	}

	// If extraction fails, return invalid party ID
	return -1
}

// generateSecureSessionID generates a cryptographically secure session ID
func generateSecureSessionID() ([]byte, error) {
	sessionID := make([]byte, 32) // 256-bit session ID
	if _, err := rand.Read(sessionID); err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}
	return sessionID, nil
}

// connectToPeer connects to a peer
func (t *TLSTransport) connectToPeer(partyID int, addr string) {
	backoff := time.Second
	maxBackoff := time.Minute

	for attempt := 0; attempt < t.config.MaxReconnectAttempts; attempt++ {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		if err := t.dialPeer(partyID, addr); err == nil {
			return
		}

		atomic.AddUint64(&t.metrics.FailedConnections, 1)

		// Exponential backoff
		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// dialPeer establishes a TLS connection to a peer
func (t *TLSTransport) dialPeer(partyID int, addr string) error {
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, t.config.TLSConfig)
	if err != nil {
		return ErrConnectionFailed
	}

	state := conn.ConnectionState()

	// Generate cryptographically secure session ID
	sessionID, err := generateSecureSessionID()
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to generate session ID: %w", err)
	}

	session := &Session{
		SessionID:    sessionID,
		PartyID:      partyID,
		LocalPartyID: t.config.PartyID,
		Created:      time.Now(),
		LastActivity: time.Now(),
		Conn:         conn,
		TLSState:     &state,
	}

	peerConn := &peerConnection{
		partyID:  partyID,
		conn:     conn,
		tlsConn:  conn,
		tlsState: &state,
		session:  session,
		lastSeen: time.Now(),
	}

	// Store connection
	t.connMu.Lock()
	t.connections[partyID] = peerConn
	t.connMu.Unlock()

	// Initialize encryption channel
	sharedSecret, err := GenerateSharedSecret()
	if err != nil {
		conn.Close()
		return err
	}

	sessionKey, err := DeriveSessionKey(sharedSecret, sessionID)
	if err != nil {
		conn.Close()
		return err
	}

	channel, err := NewAESGCMChannel(sessionKey)
	if err != nil {
		conn.Close()
		return err
	}

	t.channelsMu.Lock()
	t.channels[partyID] = channel
	t.channelsMu.Unlock()

	atomic.AddUint64(&t.metrics.TotalConnections, 1)
	t.metrics.ActiveConnections++

	return nil
}

// Send sends a message to a specific party
func (t *TLSTransport) Send(ctx context.Context, partyID int, msg *Message) error {
	if !t.running.Load() {
		return ErrTransportClosed
	}

	// Check rate limit
	if t.config.EnableRateLimiting {
		t.rateLimitMu.RLock()
		limiter := t.rateLimiters[partyID]
		t.rateLimitMu.RUnlock()

		if limiter != nil && !limiter.Allow() {
			atomic.AddUint64(&t.metrics.RateLimitedMessages, 1)
			return ErrRateLimited
		}
	}

	errChan := make(chan error, 1)

	select {
	case t.outbound <- &outboundMessage{partyID: partyID, message: msg, errChan: errChan}:
		select {
		case err := <-errChan:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(t.config.SendTimeout):
			return ErrTimeout
		}
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(t.config.SendTimeout):
		return ErrTimeout
	}
}

// Broadcast sends a message to all parties
func (t *TLSTransport) Broadcast(ctx context.Context, msg *Message) error {
	if !t.running.Load() {
		return ErrTransportClosed
	}

	var lastErr error
	for partyID := range t.config.PeerAddrs {
		if err := t.Send(ctx, partyID, msg); err != nil {
			lastErr = err
			atomic.AddUint64(&t.metrics.SendErrors, 1)
		}
	}

	return lastErr
}

// Receive receives a message from any party
func (t *TLSTransport) Receive(ctx context.Context) (*Message, error) {
	if !t.running.Load() {
		return nil, ErrTransportClosed
	}

	select {
	case msg := <-t.inbound:
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(t.config.ReceiveTimeout):
		return nil, ErrTimeout
	}
}

// sendLoop handles outbound messages
func (t *TLSTransport) sendLoop() {
	defer t.wg.Done()

	for {
		select {
		case <-t.ctx.Done():
			return

		case outMsg := <-t.outbound:
			err := t.sendMessage(outMsg.partyID, outMsg.message)

			select {
			case outMsg.errChan <- err:
			default:
			}

			if err != nil {
				atomic.AddUint64(&t.metrics.SendErrors, 1)
			} else {
				atomic.AddUint64(&t.metrics.MessagesSent, 1)
			}
		}
	}
}

// sendMessage sends a message to a peer
func (t *TLSTransport) sendMessage(partyID int, msg *Message) error {
	// Get connection
	t.connMu.RLock()
	peerConn, ok := t.connections[partyID]
	t.connMu.RUnlock()

	if !ok {
		return ErrNotConnected
	}

	peerConn.mu.Lock()
	defer peerConn.mu.Unlock()

	// Set sequence number
	msg.Sequence = peerConn.sendSeq
	peerConn.sendSeq++

	// Get encryption channel
	t.channelsMu.RLock()
	channel, ok := t.channels[partyID]
	t.channelsMu.RUnlock()

	if !ok {
		return ErrSessionNotFound
	}

	// Serialize message
	data, err := msg.Serialize()
	if err != nil {
		return err
	}

	// Encrypt payload
	encrypted, err := channel.Encrypt(data)
	if err != nil {
		return ErrEncryptionFailed
	}

	// Compute MAC
	mac := channel.ComputeMAC(encrypted)
	msg.MAC = mac

	// Write length prefix
	length := uint32(len(encrypted))
	if err := binary.Write(peerConn.conn, binary.BigEndian, length); err != nil {
		return ErrSendFailed
	}

	// Write encrypted message
	if _, err := peerConn.conn.Write(encrypted); err != nil {
		return ErrSendFailed
	}

	// Update metrics
	atomic.AddUint64(&t.metrics.BytesSent, uint64(4+len(encrypted)))

	// Audit log
	if t.auditLogger != nil {
		t.auditLogger.LogMessageSent(msg, partyID)
	}

	return nil
}

// receiveLoop handles inbound messages
func (t *TLSTransport) receiveLoop() {
	defer t.wg.Done()

	// Start receiver for each connection
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		// Get active connections
		t.connMu.RLock()
		conns := make(map[int]*peerConnection, len(t.connections))
		for id, conn := range t.connections {
			conns[id] = conn
		}
		t.connMu.RUnlock()

		// Start receiver for new connections
		for partyID, conn := range conns {
			go t.receiveFromPeer(partyID, conn)
		}

		time.Sleep(time.Second)
	}
}

// receiveFromPeer receives messages from a peer
func (t *TLSTransport) receiveFromPeer(partyID int, peerConn *peerConnection) {
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		// Read length prefix
		var length uint32
		if err := binary.Read(peerConn.conn, binary.BigEndian, &length); err != nil {
			if err != io.EOF && t.running.Load() {
				atomic.AddUint64(&t.metrics.ReceiveErrors, 1)
			}
			return
		}

		// Validate length
		if length > uint32(t.config.MaxMessageSize) {
			atomic.AddUint64(&t.metrics.ReceiveErrors, 1)
			return
		}

		// Read encrypted message
		encrypted := make([]byte, length)
		if _, err := io.ReadFull(peerConn.conn, encrypted); err != nil {
			atomic.AddUint64(&t.metrics.ReceiveErrors, 1)
			return
		}

		// Get encryption channel
		t.channelsMu.RLock()
		channel, ok := t.channels[partyID]
		t.channelsMu.RUnlock()

		if !ok {
			continue
		}

		// Decrypt message
		decrypted, err := channel.Decrypt(encrypted)
		if err != nil {
			atomic.AddUint64(&t.metrics.ReceiveErrors, 1)
			continue
		}

		// Deserialize message
		msg, err := DeserializeMessage(decrypted)
		if err != nil {
			atomic.AddUint64(&t.metrics.ReceiveErrors, 1)
			continue
		}

		// Validate sequence number
		peerConn.mu.Lock()
		if msg.Sequence != peerConn.recvSeq {
			peerConn.mu.Unlock()
			atomic.AddUint64(&t.metrics.ReceiveErrors, 1)
			continue
		}
		peerConn.recvSeq++
		peerConn.lastSeen = time.Now()
		peerConn.mu.Unlock()

		// Update metrics
		atomic.AddUint64(&t.metrics.MessagesReceived, 1)
		atomic.AddUint64(&t.metrics.BytesReceived, uint64(4+length))

		// Audit log
		if t.auditLogger != nil {
			t.auditLogger.LogMessageReceived(msg, partyID)
		}

		// Queue message
		select {
		case t.inbound <- msg:
		case <-t.ctx.Done():
			return
		default:
			// Buffer full, drop message
			atomic.AddUint64(&t.metrics.ReceiveErrors, 1)
		}
	}
}

// Stop stops the transport
func (t *TLSTransport) Stop(ctx context.Context) error {
	if !t.running.CompareAndSwap(true, false) {
		return ErrTransportClosed
	}

	// Cancel context
	t.cancel()

	// Close listener
	if t.listener != nil {
		t.listener.Close()
	}

	// Close all connections
	t.connMu.Lock()
	for _, conn := range t.connections {
		conn.conn.Close()
	}
	t.connMu.Unlock()

	// Close encryption channels
	t.channelsMu.Lock()
	for _, channel := range t.channels {
		channel.Close()
	}
	t.channelsMu.Unlock()

	// Close audit logger
	if t.auditLogger != nil {
		t.auditLogger.Close()
	}

	// Wait for goroutines
	t.wg.Wait()

	return nil
}

// LocalPartyID returns this party's ID
func (t *TLSTransport) LocalPartyID() int {
	return t.config.PartyID
}

// PeerCount returns the number of connected peers
func (t *TLSTransport) PeerCount() int {
	t.connMu.RLock()
	defer t.connMu.RUnlock()
	return len(t.connections)
}

// IsConnected checks if a specific party is connected
func (t *TLSTransport) IsConnected(partyID int) bool {
	t.connMu.RLock()
	defer t.connMu.RUnlock()
	_, ok := t.connections[partyID]
	return ok
}

// RegisterHandler registers a message handler
func (t *TLSTransport) RegisterHandler(msgType MessageType, handler HandlerFunc) error {
	t.handlersMu.Lock()
	defer t.handlersMu.Unlock()

	if _, exists := t.handlers[msgType]; exists {
		return ErrHandlerAlreadyRegistered
	}

	t.handlers[msgType] = handler
	return nil
}

// UnregisterHandler removes a message handler
func (t *TLSTransport) UnregisterHandler(msgType MessageType) error {
	t.handlersMu.Lock()
	defer t.handlersMu.Unlock()

	delete(t.handlers, msgType)
	return nil
}

// SetRateLimit sets the rate limit for a party
func (t *TLSTransport) SetRateLimit(partyID int, messagesPerSecond int) error {
	if !t.config.EnableRateLimiting {
		return ErrInvalidConfig
	}

	t.rateLimitMu.Lock()
	defer t.rateLimitMu.Unlock()

	t.rateLimiters[partyID] = newRateLimiter(messagesPerSecond)
	return nil
}

// GetPeerInfo returns information about a peer
func (t *TLSTransport) GetPeerInfo(partyID int) (*PeerInfo, error) {
	t.connMu.RLock()
	peerConn, ok := t.connections[partyID]
	t.connMu.RUnlock()

	if !ok {
		return nil, ErrNotConnected
	}

	peerConn.mu.RLock()
	defer peerConn.mu.RUnlock()

	info := &PeerInfo{
		PartyID:   partyID,
		Connected: true,
		LastSeen:  peerConn.lastSeen,
	}

	if peerConn.tlsState != nil {
		info.TLSVersion = peerConn.tlsState.Version
		info.CipherSuite = peerConn.tlsState.CipherSuite
	}

	return info, nil
}

// GetMetrics returns network metrics
func (t *TLSTransport) GetMetrics() *NetworkMetrics {
	metrics := &NetworkMetrics{
		MessagesSent:        atomic.LoadUint64(&t.metrics.MessagesSent),
		MessagesReceived:    atomic.LoadUint64(&t.metrics.MessagesReceived),
		BytesSent:           atomic.LoadUint64(&t.metrics.BytesSent),
		BytesReceived:       atomic.LoadUint64(&t.metrics.BytesReceived),
		ActiveConnections:   t.PeerCount(),
		TotalConnections:    atomic.LoadUint64(&t.metrics.TotalConnections),
		FailedConnections:   atomic.LoadUint64(&t.metrics.FailedConnections),
		SendErrors:          atomic.LoadUint64(&t.metrics.SendErrors),
		ReceiveErrors:       atomic.LoadUint64(&t.metrics.ReceiveErrors),
		TimeoutErrors:       atomic.LoadUint64(&t.metrics.TimeoutErrors),
		RateLimitedMessages: atomic.LoadUint64(&t.metrics.RateLimitedMessages),
		Uptime:              time.Since(t.startTime),
	}

	return metrics
}
