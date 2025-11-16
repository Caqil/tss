// Package network - Audit logging for security and compliance
package network

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditLogger provides secure audit logging
type AuditLogger struct {
	file     *os.File
	encoder  *json.Encoder
	mu       sync.Mutex
	enabled  bool
	filePath string
}

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	PartyID     int                    `json:"party_id"`
	RemoteParty int                    `json:"remote_party,omitempty"`
	MessageType MessageType            `json:"message_type,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	Success     bool                   `json:"success"`
	Error       string                 `json:"error,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(filePath string) (*AuditLogger, error) {
	if filePath == "" {
		return &AuditLogger{enabled: false}, nil
	}

	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}

	return &AuditLogger{
		file:     file,
		encoder:  json.NewEncoder(file),
		enabled:  true,
		filePath: filePath,
	}, nil
}

// LogMessageSent logs a sent message
func (al *AuditLogger) LogMessageSent(msg *Message, toParty int) {
	if !al.enabled {
		return
	}

	entry := &AuditEntry{
		Timestamp:   time.Now(),
		EventType:   "message_sent",
		PartyID:     msg.From,
		RemoteParty: toParty,
		MessageType: msg.Type,
		SessionID:   fmt.Sprintf("%x", msg.SessionID),
		Success:     true,
		Details: map[string]interface{}{
			"sequence":     msg.Sequence,
			"payload_size": len(msg.Payload),
		},
	}

	al.writeEntry(entry)
}

// LogMessageReceived logs a received message
func (al *AuditLogger) LogMessageReceived(msg *Message, fromParty int) {
	if !al.enabled {
		return
	}

	entry := &AuditEntry{
		Timestamp:   time.Now(),
		EventType:   "message_received",
		PartyID:     msg.To,
		RemoteParty: fromParty,
		MessageType: msg.Type,
		SessionID:   fmt.Sprintf("%x", msg.SessionID),
		Success:     true,
		Details: map[string]interface{}{
			"sequence":     msg.Sequence,
			"payload_size": len(msg.Payload),
		},
	}

	al.writeEntry(entry)
}

// LogConnectionEstablished logs a new connection
func (al *AuditLogger) LogConnectionEstablished(localParty, remoteParty int, tlsVersion uint16) {
	if !al.enabled {
		return
	}

	entry := &AuditEntry{
		Timestamp:   time.Now(),
		EventType:   "connection_established",
		PartyID:     localParty,
		RemoteParty: remoteParty,
		Success:     true,
		Details: map[string]interface{}{
			"tls_version": fmt.Sprintf("0x%04x", tlsVersion),
		},
	}

	al.writeEntry(entry)
}

// LogConnectionFailed logs a failed connection attempt
func (al *AuditLogger) LogConnectionFailed(localParty, remoteParty int, err error) {
	if !al.enabled {
		return
	}

	entry := &AuditEntry{
		Timestamp:   time.Now(),
		EventType:   "connection_failed",
		PartyID:     localParty,
		RemoteParty: remoteParty,
		Success:     false,
		Error:       err.Error(),
	}

	al.writeEntry(entry)
}

// LogRateLimitExceeded logs a rate limit violation
func (al *AuditLogger) LogRateLimitExceeded(localParty, remoteParty int) {
	if !al.enabled {
		return
	}

	entry := &AuditEntry{
		Timestamp:   time.Now(),
		EventType:   "rate_limit_exceeded",
		PartyID:     localParty,
		RemoteParty: remoteParty,
		Success:     false,
		Error:       "rate limit exceeded",
	}

	al.writeEntry(entry)
}

// LogAuthenticationFailure logs an authentication failure
func (al *AuditLogger) LogAuthenticationFailure(localParty, remoteParty int, reason string) {
	if !al.enabled {
		return
	}

	entry := &AuditEntry{
		Timestamp:   time.Now(),
		EventType:   "authentication_failed",
		PartyID:     localParty,
		RemoteParty: remoteParty,
		Success:     false,
		Error:       reason,
	}

	al.writeEntry(entry)
}

// LogEncryptionError logs an encryption/decryption error
func (al *AuditLogger) LogEncryptionError(localParty, remoteParty int, err error) {
	if !al.enabled {
		return
	}

	entry := &AuditEntry{
		Timestamp:   time.Now(),
		EventType:   "encryption_error",
		PartyID:     localParty,
		RemoteParty: remoteParty,
		Success:     false,
		Error:       err.Error(),
	}

	al.writeEntry(entry)
}

// LogReplayAttackDetected logs a detected replay attack
func (al *AuditLogger) LogReplayAttackDetected(localParty, remoteParty int, sessionID []byte) {
	if !al.enabled {
		return
	}

	entry := &AuditEntry{
		Timestamp:   time.Now(),
		EventType:   "replay_attack_detected",
		PartyID:     localParty,
		RemoteParty: remoteParty,
		SessionID:   fmt.Sprintf("%x", sessionID),
		Success:     false,
		Error:       "replay attack detected",
	}

	al.writeEntry(entry)
}

// LogKeyRotation logs a key rotation event
func (al *AuditLogger) LogKeyRotation(localParty, remoteParty int, keyVersion uint32) {
	if !al.enabled {
		return
	}

	entry := &AuditEntry{
		Timestamp:   time.Now(),
		EventType:   "key_rotation",
		PartyID:     localParty,
		RemoteParty: remoteParty,
		Success:     true,
		Details: map[string]interface{}{
			"key_version": keyVersion,
		},
	}

	al.writeEntry(entry)
}

// LogSecurityEvent logs a generic security event
func (al *AuditLogger) LogSecurityEvent(eventType string, partyID int, details map[string]interface{}) {
	if !al.enabled {
		return
	}

	entry := &AuditEntry{
		Timestamp: time.Now(),
		EventType: eventType,
		PartyID:   partyID,
		Success:   true,
		Details:   details,
	}

	al.writeEntry(entry)
}

// writeEntry writes an audit entry to the log
func (al *AuditLogger) writeEntry(entry *AuditEntry) {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.file == nil {
		return
	}

	if err := al.encoder.Encode(entry); err != nil {
		// Log to stderr if we can't write to audit log
		fmt.Fprintf(os.Stderr, "Failed to write audit log: %v\n", err)
	}
}

// Close closes the audit logger
func (al *AuditLogger) Close() error {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.file != nil {
		return al.file.Close()
	}

	return nil
}

// Rotate rotates the audit log file
func (al *AuditLogger) Rotate() error {
	al.mu.Lock()
	defer al.mu.Unlock()

	if !al.enabled {
		return nil
	}

	// Close current file
	if al.file != nil {
		al.file.Close()
	}

	// Rename old file with timestamp
	timestamp := time.Now().Format("20060102-150405")
	oldPath := fmt.Sprintf("%s.%s", al.filePath, timestamp)

	if err := os.Rename(al.filePath, oldPath); err != nil {
		return err
	}

	// Open new file
	file, err := os.OpenFile(al.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	al.file = file
	al.encoder = json.NewEncoder(file)

	return nil
}

// GetStats returns statistics about the audit log
func (al *AuditLogger) GetStats() (*AuditStats, error) {
	al.mu.Lock()
	filePath := al.filePath
	al.mu.Unlock()

	if filePath == "" {
		return &AuditStats{Enabled: false}, nil
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}

	return &AuditStats{
		Enabled:      true,
		FilePath:     filePath,
		FileSize:     info.Size(),
		LastModified: info.ModTime(),
	}, nil
}

// AuditStats contains audit log statistics
type AuditStats struct {
	Enabled      bool
	FilePath     string
	FileSize     int64
	LastModified time.Time
}
