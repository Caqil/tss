// Package network - Secure channel with authenticated encryption
package network

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// AESGCMChannel implements SecureChannel using AES-256-GCM
type AESGCMChannel struct {
	// Encryption key (32 bytes for AES-256)
	encryptKey []byte

	// MAC key for additional authentication
	macKey []byte

	// AEAD cipher for authenticated encryption
	aead cipher.AEAD

	// Nonce tracker to prevent reuse
	nonceTracker *nonceTracker

	// Mutex for thread-safe operations
	mu sync.RWMutex

	// Key rotation counter
	keyVersion uint32

	// Created timestamp
	created time.Time

	// Last key rotation
	lastRotation time.Time
}

// nonceTracker prevents nonce reuse attacks
type nonceTracker struct {
	used map[string]bool
	mu   sync.RWMutex
	// Maximum size before cleanup (prevent memory exhaustion)
	maxSize int
}

// newNonceTracker creates a new nonce tracker
func newNonceTracker(maxSize int) *nonceTracker {
	return &nonceTracker{
		used:    make(map[string]bool),
		maxSize: maxSize,
	}
}

// checkAndMarkUsed checks if nonce was used and marks it as used
func (nt *nonceTracker) checkAndMarkUsed(nonce []byte) bool {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	nonceStr := string(nonce)

	// Check if nonce was already used
	if nt.used[nonceStr] {
		return false
	}

	// Clean up if too many nonces stored
	if len(nt.used) >= nt.maxSize {
		// Clear oldest half (simple strategy)
		for k := range nt.used {
			delete(nt.used, k)
			if len(nt.used) < nt.maxSize/2 {
				break
			}
		}
	}

	// Mark as used
	nt.used[nonceStr] = true
	return true
}

// NewAESGCMChannel creates a new AES-GCM secure channel
func NewAESGCMChannel(masterKey []byte) (*AESGCMChannel, error) {
	if len(masterKey) < 32 {
		return nil, ErrEncryptionFailed
	}

	// Derive encryption and MAC keys using HKDF
	encryptKey, macKey, err := deriveKeys(masterKey)
	if err != nil {
		return nil, err
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(encryptKey)
	if err != nil {
		return nil, ErrEncryptionFailed
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrEncryptionFailed
	}

	return &AESGCMChannel{
		encryptKey:   encryptKey,
		macKey:       macKey,
		aead:         aead,
		nonceTracker: newNonceTracker(10000),
		keyVersion:   1,
		created:      time.Now(),
		lastRotation: time.Now(),
	}, nil
}

// deriveKeys derives encryption and MAC keys from master key using HKDF
func deriveKeys(masterKey []byte) (encryptKey, macKey []byte, err error) {
	// Use HKDF-SHA256 for key derivation
	salt := []byte("mpc-tss-network-v1")
	info := []byte("aes-gcm-channel")

	kdf := hkdf.New(sha256.New, masterKey, salt, info)

	// Derive 32 bytes for encryption key
	encryptKey = make([]byte, 32)
	if _, err := io.ReadFull(kdf, encryptKey); err != nil {
		return nil, nil, ErrEncryptionFailed
	}

	// Derive 32 bytes for MAC key
	macKey = make([]byte, 32)
	if _, err := io.ReadFull(kdf, macKey); err != nil {
		return nil, nil, ErrEncryptionFailed
	}

	return encryptKey, macKey, nil
}

// Encrypt encrypts and authenticates plaintext
// Format: version(4) || nonce(12) || ciphertext || tag(16)
func (c *AESGCMChannel) Encrypt(plaintext []byte) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Generate random nonce (12 bytes for GCM)
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrEncryptionFailed
	}

	// Encrypt with additional data (key version)
	additionalData := make([]byte, 4)
	binary.BigEndian.PutUint32(additionalData, c.keyVersion)

	ciphertext := c.aead.Seal(nil, nonce, plaintext, additionalData)

	// Build final message: version || nonce || ciphertext
	result := make([]byte, 4+len(nonce)+len(ciphertext))
	copy(result[0:4], additionalData)
	copy(result[4:4+len(nonce)], nonce)
	copy(result[4+len(nonce):], ciphertext)

	return result, nil
}

// Decrypt decrypts and verifies ciphertext
func (c *AESGCMChannel) Decrypt(ciphertext []byte) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	nonceSize := c.aead.NonceSize()

	// Minimum size: version(4) + nonce(12) + tag(16)
	if len(ciphertext) < 4+nonceSize+c.aead.Overhead() {
		return nil, ErrDecryptionFailed
	}

	// Extract components
	version := binary.BigEndian.Uint32(ciphertext[0:4])
	nonce := ciphertext[4 : 4+nonceSize]
	encrypted := ciphertext[4+nonceSize:]

	// Verify key version
	if version != c.keyVersion {
		return nil, ErrDecryptionFailed
	}

	// Check for nonce reuse (replay attack)
	if !c.nonceTracker.checkAndMarkUsed(nonce) {
		return nil, ErrInvalidNonce
	}

	// Additional data for authentication
	additionalData := ciphertext[0:4]

	// Decrypt and verify
	plaintext, err := c.aead.Open(nil, nonce, encrypted, additionalData)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// RotateKeys generates new encryption keys
func (c *AESGCMChannel) RotateKeys() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Generate new master key
	newMasterKey := make([]byte, 32)
	if _, err := rand.Read(newMasterKey); err != nil {
		return ErrEncryptionFailed
	}

	// Derive new keys
	encryptKey, macKey, err := deriveKeys(newMasterKey)
	if err != nil {
		return err
	}

	// Create new cipher
	block, err := aes.NewCipher(encryptKey)
	if err != nil {
		return ErrEncryptionFailed
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return ErrEncryptionFailed
	}

	// Update keys atomically
	c.encryptKey = encryptKey
	c.macKey = macKey
	c.aead = aead
	c.keyVersion++
	c.lastRotation = time.Now()

	// Clear old nonce tracker
	c.nonceTracker = newNonceTracker(10000)

	return nil
}

// ComputeMAC computes HMAC-SHA256 for a message
func (c *AESGCMChannel) ComputeMAC(data []byte) []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()

	mac := hmac.New(sha256.New, c.macKey)
	mac.Write(data)
	return mac.Sum(nil)
}

// VerifyMAC verifies HMAC-SHA256 for a message
func (c *AESGCMChannel) VerifyMAC(data, expectedMAC []byte) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	mac := hmac.New(sha256.New, c.macKey)
	mac.Write(data)
	computedMAC := mac.Sum(nil)

	return subtle.ConstantTimeCompare(computedMAC, expectedMAC) == 1
}

// KeyVersion returns the current key version
func (c *AESGCMChannel) KeyVersion() uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.keyVersion
}

// LastRotation returns when keys were last rotated
func (c *AESGCMChannel) LastRotation() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastRotation
}

// Close securely erases all key material
func (c *AESGCMChannel) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Zero out keys
	for i := range c.encryptKey {
		c.encryptKey[i] = 0
	}
	for i := range c.macKey {
		c.macKey[i] = 0
	}

	c.encryptKey = nil
	c.macKey = nil
	c.aead = nil
}

// GenerateSharedSecret generates a shared secret for a session
func GenerateSharedSecret() ([]byte, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, ErrEncryptionFailed
	}
	return secret, nil
}

// DeriveSessionKey derives a session-specific key from a shared secret
func DeriveSessionKey(sharedSecret, sessionID []byte) ([]byte, error) {
	if len(sharedSecret) < 32 {
		return nil, ErrEncryptionFailed
	}

	// Use HKDF to derive session key
	salt := []byte("mpc-tss-session-key-v1")
	info := append([]byte("session:"), sessionID...)

	kdf := hkdf.New(sha256.New, sharedSecret, salt, info)

	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, sessionKey); err != nil {
		return nil, ErrEncryptionFailed
	}

	return sessionKey, nil
}
