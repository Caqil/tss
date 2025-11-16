// Package storage - Comprehensive tests for secure key share storage
package storage

import (
	"crypto/rand"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/Caqil/mpc-tss/pkg/crypto/curve"
	"github.com/Caqil/mpc-tss/pkg/keygen"
)

// createTestKeyShare creates a test key share
func createTestKeyShare(partyID, threshold, total int) *keygen.KeyShare {
	c, _ := curve.NewCurve(curve.Secp256k1)

	// Generate random values for testing
	secret := new(big.Int).SetInt64(int64(partyID + 1000))

	// Create public key point
	publicKey, _ := c.ScalarBaseMult(secret)

	return &keygen.KeyShare{
		PartyID:   partyID,
		Threshold: threshold,
		Parties:   total,
		Share:     secret,
		PublicKey: publicKey,
		Curve:     c,
	}
}

func TestDefaultStorageConfig(t *testing.T) {
	config := DefaultStorageConfig("/tmp/test.key")

	if config.FilePath != "/tmp/test.key" {
		t.Errorf("Expected FilePath /tmp/test.key, got %s", config.FilePath)
	}

	if config.FileMode != 0600 {
		t.Errorf("Expected FileMode 0600, got %o", config.FileMode)
	}

	if config.Argon2Time < 1 {
		t.Error("Argon2Time should be at least 1")
	}

	if config.Argon2Memory < 8*1024 {
		t.Error("Argon2Memory should be at least 8 MB")
	}

	if config.Argon2KeyLen != 32 {
		t.Error("Argon2KeyLen should be 32 for AES-256")
	}

	if err := config.Validate(); err != nil {
		t.Errorf("Default config should be valid: %v", err)
	}
}

func TestStorageConfigValidation(t *testing.T) {
	tests := []struct {
		name         string
		modifyConfig func(*StorageConfig)
		expectError  bool
	}{
		{
			name:         "valid config",
			modifyConfig: func(c *StorageConfig) {},
			expectError:  false,
		},
		{
			name: "empty file path",
			modifyConfig: func(c *StorageConfig) {
				c.FilePath = ""
			},
			expectError: true,
		},
		{
			name: "insecure file permissions",
			modifyConfig: func(c *StorageConfig) {
				c.FileMode = 0644
			},
			expectError: true,
		},
		{
			name: "low argon2 time",
			modifyConfig: func(c *StorageConfig) {
				c.Argon2Time = 0
			},
			expectError: true,
		},
		{
			name: "low argon2 memory",
			modifyConfig: func(c *StorageConfig) {
				c.Argon2Memory = 1024
			},
			expectError: true,
		},
		{
			name: "invalid key length",
			modifyConfig: func(c *StorageConfig) {
				c.Argon2KeyLen = 16
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultStorageConfig("/tmp/test.key")
			tt.modifyConfig(config)

			err := config.Validate()
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestPasswordValidation(t *testing.T) {
	config := DefaultStorageConfig("/tmp/test.key")
	config.MinPasswordLength = 12

	tests := []struct {
		name        string
		password    string
		expectError bool
	}{
		{"strong password", "MySecurePass123!", false},
		{"minimum length", "Password1234", false},
		{"too short", "Pass123", true},
		{"no numbers", "PasswordOnly", true},
		{"no letters", "123456789012", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := config.validatePassword(tt.password)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1, err := generateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	if len(salt1) != 32 {
		t.Errorf("Expected salt length 32, got %d", len(salt1))
	}

	// Generate another salt and ensure they're different
	salt2, err := generateSalt()
	if err != nil {
		t.Fatalf("Failed to generate second salt: %v", err)
	}

	if string(salt1) == string(salt2) {
		t.Error("Generated salts should be different")
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce1, err := generateNonce()
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	if len(nonce1) != 12 {
		t.Errorf("Expected nonce length 12, got %d", len(nonce1))
	}

	// Generate another nonce and ensure they're different
	nonce2, err := generateNonce()
	if err != nil {
		t.Fatalf("Failed to generate second nonce: %v", err)
	}

	if string(nonce1) == string(nonce2) {
		t.Error("Generated nonces should be different")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	// Generate random key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	plaintext := []byte("This is a secret message for testing encryption")

	// Encrypt
	nonce, ciphertext, err := encryptData(plaintext, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if len(nonce) != 12 {
		t.Errorf("Expected nonce length 12, got %d", len(nonce))
	}

	if len(ciphertext) == 0 {
		t.Error("Ciphertext should not be empty")
	}

	// Decrypt
	decrypted, err := decryptData(ciphertext, nonce, key)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted data doesn't match original.\nExpected: %s\nGot: %s",
			string(plaintext), string(decrypted))
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	plaintext := []byte("Secret message")

	nonce, ciphertext, err := encryptData(plaintext, key1)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Try to decrypt with wrong key
	_, err = decryptData(ciphertext, nonce, key2)
	if err != ErrInvalidPassword {
		t.Errorf("Expected ErrInvalidPassword, got %v", err)
	}
}

func TestFileStorage_SaveAndLoad(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "keyshare.enc")

	config := DefaultStorageConfig(filePath)
	storage, err := NewFileStorage(config)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	// Create test key share
	share := createTestKeyShare(1, 2, 3)
	password := "SecurePassword123!"

	// Save
	if err := storage.Save(share, password); err != nil {
		t.Fatalf("Failed to save key share: %v", err)
	}

	// Verify file exists
	if !storage.Exists() {
		t.Error("Key share file should exist")
	}

	// Load
	loadedShare, err := storage.Load(password)
	if err != nil {
		t.Fatalf("Failed to load key share: %v", err)
	}

	// Verify loaded data
	if loadedShare.PartyID != share.PartyID {
		t.Errorf("PartyID mismatch: expected %d, got %d", share.PartyID, loadedShare.PartyID)
	}

	if loadedShare.Threshold != share.Threshold {
		t.Errorf("Threshold mismatch: expected %d, got %d", share.Threshold, loadedShare.Threshold)
	}

	if loadedShare.Parties != share.Parties {
		t.Errorf("Parties mismatch: expected %d, got %d", share.Parties, loadedShare.Parties)
	}

	if loadedShare.Share.Cmp(share.Share) != 0 {
		t.Error("Share mismatch")
	}
}

func TestFileStorage_LoadWithWrongPassword(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "keyshare.enc")

	config := DefaultStorageConfig(filePath)
	storage, err := NewFileStorage(config)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	share := createTestKeyShare(1, 2, 3)
	password := "CorrectPassword123!"

	// Save
	if err := storage.Save(share, password); err != nil {
		t.Fatalf("Failed to save key share: %v", err)
	}

	// Try to load with wrong password
	_, err = storage.Load("WrongPassword123!")
	if err != ErrInvalidPassword {
		t.Errorf("Expected ErrInvalidPassword, got %v", err)
	}
}

func TestFileStorage_Delete(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "keyshare.enc")

	config := DefaultStorageConfig(filePath)
	storage, err := NewFileStorage(config)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	share := createTestKeyShare(1, 2, 3)
	password := "SecurePassword123!"

	// Save
	if err := storage.Save(share, password); err != nil {
		t.Fatalf("Failed to save key share: %v", err)
	}

	// Delete
	if err := storage.Delete(); err != nil {
		t.Fatalf("Failed to delete key share: %v", err)
	}

	// Verify file doesn't exist
	if storage.Exists() {
		t.Error("Key share file should not exist after deletion")
	}

	// Try to delete again
	if err := storage.Delete(); err != ErrKeyShareNotFound {
		t.Errorf("Expected ErrKeyShareNotFound, got %v", err)
	}
}

func TestFileStorage_Backup(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "keyshare.enc")
	backupPath := filepath.Join(tmpDir, "keyshare.backup.enc")

	config := DefaultStorageConfig(filePath)
	storage, err := NewFileStorage(config)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	share := createTestKeyShare(1, 2, 3)
	password := "SecurePassword123!"

	// Save
	if err := storage.Save(share, password); err != nil {
		t.Fatalf("Failed to save key share: %v", err)
	}

	// Backup
	if err := storage.Backup(backupPath); err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	// Verify backup file exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Error("Backup file should exist")
	}

	// Load from backup
	backupConfig := DefaultStorageConfig(backupPath)
	backupStorage, err := NewFileStorage(backupConfig)
	if err != nil {
		t.Fatalf("Failed to create backup storage: %v", err)
	}

	loadedShare, err := backupStorage.Load(password)
	if err != nil {
		t.Fatalf("Failed to load from backup: %v", err)
	}

	if loadedShare.PartyID != share.PartyID {
		t.Error("Backup data doesn't match original")
	}
}

func TestFileStorage_Restore(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "keyshare.enc")
	backupPath := filepath.Join(tmpDir, "keyshare.backup.enc")

	config := DefaultStorageConfig(filePath)
	storage, err := NewFileStorage(config)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	share := createTestKeyShare(1, 2, 3)
	password := "SecurePassword123!"

	// Save and backup
	if err := storage.Save(share, password); err != nil {
		t.Fatalf("Failed to save key share: %v", err)
	}

	if err := storage.Backup(backupPath); err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	// Delete original
	if err := storage.Delete(); err != nil {
		t.Fatalf("Failed to delete original: %v", err)
	}

	// Restore from backup
	if err := storage.Restore(backupPath, password); err != nil {
		t.Fatalf("Failed to restore from backup: %v", err)
	}

	// Verify restored data
	loadedShare, err := storage.Load(password)
	if err != nil {
		t.Fatalf("Failed to load restored key share: %v", err)
	}

	if loadedShare.PartyID != share.PartyID {
		t.Error("Restored data doesn't match original")
	}
}

func TestFileStorage_GetMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "keyshare.enc")

	config := DefaultStorageConfig(filePath)
	storage, err := NewFileStorage(config)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	share := createTestKeyShare(1, 2, 3)
	password := "SecurePassword123!"

	// Save
	if err := storage.Save(share, password); err != nil {
		t.Fatalf("Failed to save key share: %v", err)
	}

	// Get metadata
	metadata, err := storage.GetMetadata()
	if err != nil {
		t.Fatalf("Failed to get metadata: %v", err)
	}

	if metadata.PartyID != share.PartyID {
		t.Errorf("Metadata PartyID mismatch: expected %d, got %d", share.PartyID, metadata.PartyID)
	}

	if metadata.Threshold != share.Threshold {
		t.Errorf("Metadata Threshold mismatch: expected %d, got %d", share.Threshold, metadata.Threshold)
	}

	if metadata.EncryptionAlg != "AES-256-GCM" {
		t.Errorf("Expected encryption algorithm AES-256-GCM, got %s", metadata.EncryptionAlg)
	}

	if metadata.KDFAlg != "Argon2id" {
		t.Errorf("Expected KDF algorithm Argon2id, got %s", metadata.KDFAlg)
	}
}

func TestFileStorage_ChangePassword(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "keyshare.enc")

	config := DefaultStorageConfig(filePath)
	storage, err := NewFileStorage(config)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	share := createTestKeyShare(1, 2, 3)
	oldPassword := "OldPassword123!"
	newPassword := "NewPassword456!"

	// Save with old password
	if err := storage.Save(share, oldPassword); err != nil {
		t.Fatalf("Failed to save key share: %v", err)
	}

	// Change password
	if err := storage.ChangePassword(oldPassword, newPassword); err != nil {
		t.Fatalf("Failed to change password: %v", err)
	}

	// Try to load with old password (should fail)
	_, err = storage.Load(oldPassword)
	if err != ErrInvalidPassword {
		t.Errorf("Expected ErrInvalidPassword with old password, got %v", err)
	}

	// Load with new password (should succeed)
	loadedShare, err := storage.Load(newPassword)
	if err != nil {
		t.Fatalf("Failed to load with new password: %v", err)
	}

	if loadedShare.PartyID != share.PartyID {
		t.Error("Data corrupted after password change")
	}
}

func TestFileStorage_Verify(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "keyshare.enc")

	config := DefaultStorageConfig(filePath)
	storage, err := NewFileStorage(config)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	share := createTestKeyShare(1, 2, 3)
	password := "SecurePassword123!"

	// Save
	if err := storage.Save(share, password); err != nil {
		t.Fatalf("Failed to save key share: %v", err)
	}

	// Verify with correct password
	if err := storage.Verify(password); err != nil {
		t.Errorf("Verification should succeed: %v", err)
	}

	// Verify with wrong password
	if err := storage.Verify("WrongPassword123!"); err != ErrInvalidPassword {
		t.Errorf("Expected ErrInvalidPassword, got %v", err)
	}
}

func TestSecureZero(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	secureZero(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d should be 0, got %d", i, b)
		}
	}
}

func TestFilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "keyshare.enc")

	config := DefaultStorageConfig(filePath)
	storage, err := NewFileStorage(config)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	share := createTestKeyShare(1, 2, 3)
	password := "SecurePassword123!"

	// Save
	if err := storage.Save(share, password); err != nil {
		t.Fatalf("Failed to save key share: %v", err)
	}

	// Check file permissions
	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("Expected file permissions 0600, got %o", info.Mode().Perm())
	}
}

func TestMultipleKeyShares(t *testing.T) {
	tmpDir := t.TempDir()

	// Create multiple storages for different parties
	parties := []struct {
		partyID  int
		password string
	}{
		{1, "Party1Pass123!"},
		{2, "Party2Pass456!"},
		{3, "Party3Pass789!"},
	}

	for _, p := range parties {
		filePath := filepath.Join(tmpDir, "keyshare_party_"+string(rune(p.partyID+48))+".enc")
		config := DefaultStorageConfig(filePath)
		storage, err := NewFileStorage(config)
		if err != nil {
			t.Fatalf("Failed to create storage for party %d: %v", p.partyID, err)
		}

		share := createTestKeyShare(p.partyID, 2, 3)
		if err := storage.Save(share, p.password); err != nil {
			t.Fatalf("Failed to save key share for party %d: %v", p.partyID, err)
		}

		// Verify each can be loaded
		loadedShare, err := storage.Load(p.password)
		if err != nil {
			t.Fatalf("Failed to load key share for party %d: %v", p.partyID, err)
		}

		if loadedShare.PartyID != p.partyID {
			t.Errorf("Party %d: PartyID mismatch", p.partyID)
		}
	}
}

// Benchmark tests
func BenchmarkSave(b *testing.B) {
	tmpDir := b.TempDir()
	filePath := filepath.Join(tmpDir, "keyshare.enc")

	config := DefaultStorageConfig(filePath)
	storage, _ := NewFileStorage(config)

	share := createTestKeyShare(1, 2, 3)
	password := "SecurePassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		storage.Save(share, password)
	}
}

func BenchmarkLoad(b *testing.B) {
	tmpDir := b.TempDir()
	filePath := filepath.Join(tmpDir, "keyshare.enc")

	config := DefaultStorageConfig(filePath)
	storage, _ := NewFileStorage(config)

	share := createTestKeyShare(1, 2, 3)
	password := "SecurePassword123!"
	storage.Save(share, password)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		storage.Load(password)
	}
}

func BenchmarkEncryption(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := []byte("This is a test message for benchmarking encryption performance")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptData(plaintext, key)
	}
}

func BenchmarkDecryption(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := []byte("This is a test message for benchmarking decryption performance")
	nonce, ciphertext, _ := encryptData(plaintext, key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decryptData(ciphertext, nonce, key)
	}
}
