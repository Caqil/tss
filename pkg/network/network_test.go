package network

import (
	"crypto/rand"
	"crypto/tls"
	"os"
	"testing"
	"time"
)

// TestMessageSerialization tests message serialization
func TestMessageSerialization(t *testing.T) {
	sessionID := make([]byte, 16)
	rand.Read(sessionID)

	payload := []byte("test payload data")
	nonce := make([]byte, 12)
	rand.Read(nonce)

	msg := &Message{
		Type:      MessageTypeDKGRound1,
		From:      0,
		To:        1,
		SessionID: sessionID,
		Payload:   payload,
		MAC:       make([]byte, 32),
		Timestamp: time.Now(),
		Nonce:     nonce,
		Sequence:  123,
	}

	// Serialize
	data, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Serialization failed: %v", err)
	}

	// Deserialize
	msg2, err := DeserializeMessage(data)
	if err != nil {
		t.Fatalf("Deserialization failed: %v", err)
	}

	// Verify fields
	if msg2.Type != msg.Type {
		t.Errorf("Type mismatch: got %v, want %v", msg2.Type, msg.Type)
	}

	if msg2.From != msg.From {
		t.Errorf("From mismatch: got %d, want %d", msg2.From, msg.From)
	}

	if msg2.To != msg.To {
		t.Errorf("To mismatch: got %d, want %d", msg2.To, msg.To)
	}

	if msg2.Sequence != msg.Sequence {
		t.Errorf("Sequence mismatch: got %d, want %d", msg2.Sequence, msg.Sequence)
	}

	if len(msg2.Payload) != len(msg.Payload) {
		t.Errorf("Payload length mismatch: got %d, want %d", len(msg2.Payload), len(msg.Payload))
	}
}

// TestMessageValidation tests message validation
func TestMessageValidation(t *testing.T) {
	sessionID := make([]byte, 16)
	rand.Read(sessionID)

	validMsg := &Message{
		Type:      MessageTypeSignRound1,
		From:      0,
		To:        1,
		SessionID: sessionID,
		Payload:   []byte("test"),
		Nonce:     make([]byte, 12),
		Timestamp: time.Now(),
	}

	// Valid message should pass
	if err := ValidateMessage(validMsg, 1024*1024); err != nil {
		t.Errorf("Valid message failed validation: %v", err)
	}

	// Nil message
	if err := ValidateMessage(nil, 1024); err != ErrInvalidMessage {
		t.Errorf("Expected ErrInvalidMessage for nil message, got %v", err)
	}

	// Invalid From
	invalidMsg := *validMsg
	invalidMsg.From = -1
	if err := ValidateMessage(&invalidMsg, 1024); err != ErrInvalidPartyID {
		t.Errorf("Expected ErrInvalidPartyID for invalid From, got %v", err)
	}

	// Empty SessionID
	invalidMsg = *validMsg
	invalidMsg.SessionID = nil
	if err := ValidateMessage(&invalidMsg, 1024); err != ErrInvalidMessage {
		t.Errorf("Expected ErrInvalidMessage for empty SessionID, got %v", err)
	}

	// Empty Nonce
	invalidMsg = *validMsg
	invalidMsg.Nonce = nil
	if err := ValidateMessage(&invalidMsg, 1024); err != ErrInvalidNonce {
		t.Errorf("Expected ErrInvalidNonce for empty Nonce, got %v", err)
	}

	// Oversized payload
	invalidMsg = *validMsg
	invalidMsg.Payload = make([]byte, 2048)
	if err := ValidateMessage(&invalidMsg, 1024); err != ErrMessageTooLarge {
		t.Errorf("Expected ErrMessageTooLarge for oversized payload, got %v", err)
	}
}

// TestMessageTypeString tests message type string representation
func TestMessageTypeString(t *testing.T) {
	tests := []struct {
		msgType MessageType
		want    string
	}{
		{MessageTypeDKGRound1, "DKG_ROUND_1"},
		{MessageTypeSignRound1, "SIGN_ROUND_1"},
		{MessageTypeHeartbeat, "HEARTBEAT"},
		{MessageType(255), "UNKNOWN"},
	}

	for _, tt := range tests {
		got := tt.msgType.String()
		if got != tt.want {
			t.Errorf("MessageType(%d).String() = %s, want %s", tt.msgType, got, tt.want)
		}
	}
}

// TestMessageClone tests message cloning
func TestMessageClone(t *testing.T) {
	original := &Message{
		Type:      MessageTypeSignRound2,
		From:      1,
		To:        2,
		SessionID: []byte("session123"),
		Payload:   []byte("payload"),
		MAC:       []byte("mac"),
		Nonce:     []byte("nonce"),
		Sequence:  456,
		Timestamp: time.Now(),
	}

	clone := original.Clone()

	// Verify clone matches original
	if clone.Type != original.Type {
		t.Error("Clone type mismatch")
	}
	if clone.From != original.From {
		t.Error("Clone From mismatch")
	}
	if clone.To != original.To {
		t.Error("Clone To mismatch")
	}

	// Verify deep copy (modifying clone doesn't affect original)
	clone.Payload[0] = 0xFF
	if original.Payload[0] == 0xFF {
		t.Error("Clone modified original payload")
	}
}

// TestTransportConfig tests transport configuration
func TestTransportConfig(t *testing.T) {
	// Valid config
	config := DefaultTransportConfig(0, 3)
	config.ListenAddr = "127.0.0.1:9000"
	config.PeerAddrs = map[int]string{
		1: "127.0.0.1:9001",
		2: "127.0.0.1:9002",
	}

	if err := config.Validate(); err != nil {
		t.Errorf("Valid config failed validation: %v", err)
	}

	// Invalid party ID
	invalidConfig := *config
	invalidConfig.PartyID = -1
	if err := invalidConfig.Validate(); err != ErrInvalidPartyID {
		t.Errorf("Expected ErrInvalidPartyID, got %v", err)
	}

	// Invalid total parties
	invalidConfig = *config
	invalidConfig.TotalParties = 1
	if err := invalidConfig.Validate(); err != ErrInvalidPartyCount {
		t.Errorf("Expected ErrInvalidPartyCount, got %v", err)
	}

	// Wrong number of peer addresses
	invalidConfig = *config
	invalidConfig.PeerAddrs = map[int]string{
		1: "127.0.0.1:9001",
	}
	if err := invalidConfig.Validate(); err != ErrInvalidPeerAddrs {
		t.Errorf("Expected ErrInvalidPeerAddrs, got %v", err)
	}

	// Self connection
	invalidConfig = *config
	invalidConfig.PeerAddrs = map[int]string{
		0: "127.0.0.1:9000",
		1: "127.0.0.1:9001",
	}
	if err := invalidConfig.Validate(); err != ErrSelfConnection {
		t.Errorf("Expected ErrSelfConnection, got %v", err)
	}
}

// TestAESGCMChannel tests encryption channel
func TestAESGCMChannel(t *testing.T) {
	masterKey := make([]byte, 32)
	rand.Read(masterKey)

	channel, err := NewAESGCMChannel(masterKey)
	if err != nil {
		t.Fatalf("Failed to create channel: %v", err)
	}
	defer channel.Close()

	plaintext := []byte("secret message")

	// Encrypt
	ciphertext, err := channel.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt
	decrypted, err := channel.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text doesn't match: got %s, want %s", decrypted, plaintext)
	}

	// Test replay attack protection
	_, err = channel.Decrypt(ciphertext)
	if err != ErrInvalidNonce {
		t.Errorf("Expected ErrInvalidNonce for replayed ciphertext, got %v", err)
	}
}

// TestKeyRotation tests key rotation
func TestKeyRotation(t *testing.T) {
	masterKey := make([]byte, 32)
	rand.Read(masterKey)

	channel, err := NewAESGCMChannel(masterKey)
	if err != nil {
		t.Fatalf("Failed to create channel: %v", err)
	}
	defer channel.Close()

	originalVersion := channel.KeyVersion()

	// Rotate keys
	if err := channel.RotateKeys(); err != nil {
		t.Fatalf("Key rotation failed: %v", err)
	}

	newVersion := channel.KeyVersion()

	if newVersion != originalVersion+1 {
		t.Errorf("Key version not incremented: got %d, want %d", newVersion, originalVersion+1)
	}

	// Verify encryption still works
	plaintext := []byte("test after rotation")
	ciphertext, err := channel.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption after rotation failed: %v", err)
	}

	decrypted, err := channel.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decryption after rotation failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Error("Decryption mismatch after rotation")
	}
}

// TestRateLimiter tests rate limiting
func TestRateLimiter(t *testing.T) {
	limiter := newRateLimiter(10) // 10 messages/second

	// Should allow first 20 messages immediately (burst = rate * 2)
	for i := 0; i < 20; i++ {
		if !limiter.Allow() {
			t.Errorf("Message %d was rate limited", i)
		}
	}

	// Should block additional messages after burst
	if limiter.Allow() {
		t.Error("Rate limiter allowed message beyond burst limit")
	}

	// Wait and verify tokens are refilled
	time.Sleep(1 * time.Second)

	allowed := 0
	for i := 0; i < 15; i++ {
		if limiter.Allow() {
			allowed++
		}
	}

	if allowed < 8 {
		t.Errorf("Rate limiter should allow ~10 messages after 1 second, got %d", allowed)
	}
}

// TestRateLimitManager tests rate limit manager
func TestRateLimitManager(t *testing.T) {
	manager := NewRateLimitManager()

	// Set limits
	manager.SetLimit(0, 100)
	manager.SetLimit(1, 50)

	// Check limits
	for i := 0; i < 100; i++ {
		if !manager.CheckLimit(0) {
			t.Errorf("Party 0 rate limited at message %d", i)
			break
		}
	}

	// Get stats
	stats := manager.GetStats()
	if len(stats) != 2 {
		t.Errorf("Expected 2 rate limiters, got %d", len(stats))
	}

	// Remove limit
	manager.RemoveLimit(1)
	stats = manager.GetStats()
	if len(stats) != 1 {
		t.Errorf("Expected 1 rate limiter after removal, got %d", len(stats))
	}
}

// TestAdaptiveRateLimiter tests adaptive rate limiting
func TestAdaptiveRateLimiter(t *testing.T) {
	limiter := NewAdaptiveRateLimiter(100, 10, 500)

	initialRate := limiter.CurrentRate()

	// Record successes
	for i := 0; i < 100; i++ {
		limiter.RecordSuccess()
	}

	// Rate should increase
	if limiter.CurrentRate() <= initialRate {
		t.Error("Rate did not increase after successes")
	}

	// Record errors
	for i := 0; i < 20; i++ {
		limiter.RecordError()
	}

	// Rate should decrease
	if limiter.CurrentRate() >= initialRate {
		t.Error("Rate did not decrease after errors")
	}
}

// TestConnectionThrottler tests connection throttling
func TestConnectionThrottler(t *testing.T) {
	throttler := NewConnectionThrottler(3, 1*time.Second)

	addr := "192.168.1.1"

	// Should allow first 3 connections
	for i := 0; i < 3; i++ {
		if !throttler.AllowConnection(addr) {
			t.Errorf("Connection %d was throttled", i)
		}
	}

	// Should block 4th connection
	if throttler.AllowConnection(addr) {
		t.Error("Connection throttler allowed 4th connection")
	}

	// Wait for window to expire
	time.Sleep(1500 * time.Millisecond)

	// Should allow connections again
	if !throttler.AllowConnection(addr) {
		t.Error("Connection throttler blocked after window expiry")
	}
}

// TestAuditLogger tests audit logging
func TestAuditLogger(t *testing.T) {
	tmpFile := "/tmp/test-audit.log"
	defer os.Remove(tmpFile)

	logger, err := NewAuditLogger(tmpFile)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}
	defer logger.Close()

	// Log various events
	msg := &Message{
		Type:      MessageTypeSignRound1,
		From:      0,
		To:        1,
		SessionID: []byte("test-session"),
		Sequence:  1,
	}

	logger.LogMessageSent(msg, 1)
	logger.LogMessageReceived(msg, 0)
	logger.LogConnectionEstablished(0, 1, tls.VersionTLS13)

	// Get stats
	stats, err := logger.GetStats()
	if err != nil {
		t.Fatalf("Failed to get stats: %v", err)
	}

	if !stats.Enabled {
		t.Error("Audit logger should be enabled")
	}

	if stats.FileSize == 0 {
		t.Error("Audit log should have data")
	}
}

// TestGenerateSharedSecret tests shared secret generation
func TestGenerateSharedSecret(t *testing.T) {
	secret1, err := GenerateSharedSecret()
	if err != nil {
		t.Fatalf("Failed to generate shared secret: %v", err)
	}

	if len(secret1) != 32 {
		t.Errorf("Expected 32-byte secret, got %d bytes", len(secret1))
	}

	secret2, err := GenerateSharedSecret()
	if err != nil {
		t.Fatalf("Failed to generate second shared secret: %v", err)
	}

	// Secrets should be different
	if string(secret1) == string(secret2) {
		t.Error("Generated secrets should be different")
	}
}

// TestDeriveSessionKey tests session key derivation
func TestDeriveSessionKey(t *testing.T) {
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	sessionID := []byte("session-123")

	key1, err := DeriveSessionKey(sharedSecret, sessionID)
	if err != nil {
		t.Fatalf("Failed to derive session key: %v", err)
	}

	if len(key1) != 32 {
		t.Errorf("Expected 32-byte key, got %d bytes", len(key1))
	}

	// Same inputs should produce same key
	key2, err := DeriveSessionKey(sharedSecret, sessionID)
	if err != nil {
		t.Fatalf("Failed to derive second session key: %v", err)
	}

	if string(key1) != string(key2) {
		t.Error("Same inputs should produce same session key")
	}

	// Different session ID should produce different key
	key3, err := DeriveSessionKey(sharedSecret, []byte("session-456"))
	if err != nil {
		t.Fatalf("Failed to derive third session key: %v", err)
	}

	if string(key1) == string(key3) {
		t.Error("Different session IDs should produce different keys")
	}
}

// Benchmark tests
func BenchmarkMessageSerialization(b *testing.B) {
	msg := &Message{
		Type:      MessageTypeSignRound1,
		From:      0,
		To:        1,
		SessionID: make([]byte, 16),
		Payload:   make([]byte, 1024),
		MAC:       make([]byte, 32),
		Nonce:     make([]byte, 12),
		Timestamp: time.Now(),
		Sequence:  123,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg.Serialize()
	}
}

func BenchmarkEncryption(b *testing.B) {
	masterKey := make([]byte, 32)
	rand.Read(masterKey)

	channel, _ := NewAESGCMChannel(masterKey)
	defer channel.Close()

	plaintext := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		channel.Encrypt(plaintext)
	}
}

func BenchmarkDecryption(b *testing.B) {
	masterKey := make([]byte, 32)
	rand.Read(masterKey)

	channel, _ := NewAESGCMChannel(masterKey)
	defer channel.Close()

	plaintext := make([]byte, 1024)
	ciphertext, _ := channel.Encrypt(plaintext)

	// Need fresh channel for each iteration to avoid nonce reuse check
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		channel, _ = NewAESGCMChannel(masterKey)
		ciphertext, _ = channel.Encrypt(plaintext)
		b.StartTimer()

		channel.Decrypt(ciphertext)
	}
}
