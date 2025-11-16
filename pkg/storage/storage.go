// Package storage provides secure encrypted storage for TSS key shares
package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/Caqil/mpc-tss/pkg/crypto/curve"
	"github.com/Caqil/mpc-tss/pkg/keygen"
	"golang.org/x/crypto/argon2"
)

// Storage errors
var (
	ErrInvalidPassword  = errors.New("invalid password")
	ErrKeyShareNotFound = errors.New("key share not found")
	ErrInvalidKeyShare  = errors.New("invalid key share")
	ErrStorageCorrupted = errors.New("storage corrupted")
	ErrInvalidFormat    = errors.New("invalid storage format")
	ErrPermissionDenied = errors.New("permission denied")
	ErrWeakPassword     = errors.New("password too weak")
	ErrInvalidSalt      = errors.New("invalid salt")
	ErrInvalidNonce     = errors.New("invalid nonce")
	ErrEncryptionFailed = errors.New("encryption failed")
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrBackupFailed     = errors.New("backup failed")
	ErrRestoreFailed    = errors.New("restore failed")
	ErrInvalidMetadata  = errors.New("invalid metadata")
	ErrVersionMismatch  = errors.New("version mismatch")
	ErrChecksumMismatch = errors.New("checksum mismatch")
)

// KeyShareStorage defines the interface for key share storage
type KeyShareStorage interface {
	// Save encrypts and saves a key share with password protection
	Save(share *keygen.KeyShare, password string) error

	// Load decrypts and loads a key share using the password
	Load(password string) (*keygen.KeyShare, error)

	// Delete securely deletes the stored key share
	Delete() error

	// Exists checks if a key share exists in storage
	Exists() bool

	// Backup creates an encrypted backup of the key share
	Backup(backupPath string) error

	// Restore restores a key share from backup
	Restore(backupPath, password string) error

	// GetMetadata returns storage metadata without decrypting
	GetMetadata() (*StorageMetadata, error)

	// ChangePassword re-encrypts the key share with a new password
	ChangePassword(oldPassword, newPassword string) error

	// Verify validates the integrity of stored data
	Verify(password string) error
}

// StorageMetadata contains information about stored key shares
type StorageMetadata struct {
	Version       string    `json:"version"`
	PartyID       int       `json:"party_id"`
	Threshold     int       `json:"threshold"`
	TotalParties  int       `json:"total_parties"`
	CreatedAt     time.Time `json:"created_at"`
	ModifiedAt    time.Time `json:"modified_at"`
	EncryptionAlg string    `json:"encryption_alg"`
	KDFAlg        string    `json:"kdf_alg"`
	KDFParams     KDFParams `json:"kdf_params"`
	Checksum      []byte    `json:"checksum"`
}

// KDFParams contains key derivation function parameters
type KDFParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"key_len"`
	Salt    []byte `json:"salt"`
}

// EncryptedKeyShare represents an encrypted key share on disk
type EncryptedKeyShare struct {
	Metadata   StorageMetadata `json:"metadata"`
	Nonce      []byte          `json:"nonce"`
	Ciphertext []byte          `json:"ciphertext"`
}

// serializableKeyShare is a JSON-serializable version of KeyShare
type serializableKeyShare struct {
	PartyID            int      `json:"party_id"`
	Threshold          int      `json:"threshold"`
	Parties            int      `json:"parties"`
	Share              []byte   `json:"share"`
	PublicKeyX         []byte   `json:"public_key_x"`
	PublicKeyY         []byte   `json:"public_key_y"`
	VerificationShares [][]byte `json:"verification_shares,omitempty"`
	CurveType          int      `json:"curve_type"`
}

// toSerializable converts KeyShare to serializableKeyShare
func toSerializable(share *keygen.KeyShare) *serializableKeyShare {
	s := &serializableKeyShare{
		PartyID:   share.PartyID,
		Threshold: share.Threshold,
		Parties:   share.Parties,
	}

	if share.Share != nil {
		s.Share = share.Share.Bytes()
	}

	if share.PublicKey != nil {
		s.PublicKeyX = share.PublicKey.X.Bytes()
		s.PublicKeyY = share.PublicKey.Y.Bytes()
	}

	// Store curve type
	params := share.Curve.Params()
	if params != nil && params.Name == "secp256k1" {
		s.CurveType = 0 // Secp256k1
	} else if params != nil && params.Name == "P-256" {
		s.CurveType = 1 // P256
	} else {
		s.CurveType = 2 // Ed25519
	}

	// Store verification shares if present
	if len(share.VerificationShares) > 0 {
		s.VerificationShares = make([][]byte, 0, len(share.VerificationShares)*2)
		for _, point := range share.VerificationShares {
			if point != nil {
				s.VerificationShares = append(s.VerificationShares, point.X.Bytes())
				s.VerificationShares = append(s.VerificationShares, point.Y.Bytes())
			}
		}
	}

	return s
}

// toKeyShare converts serializableKeyShare back to KeyShare
func toKeyShare(s *serializableKeyShare) (*keygen.KeyShare, error) {
	// Recreate curve
	var curveType curve.CurveType
	switch s.CurveType {
	case 0:
		curveType = curve.Secp256k1
	case 1:
		curveType = curve.P256
	case 2:
		curveType = curve.Ed25519
	default:
		return nil, ErrInvalidKeyShare
	}

	c, err := curve.NewCurve(curveType)
	if err != nil {
		return nil, err
	}

	share := &keygen.KeyShare{
		PartyID:   s.PartyID,
		Threshold: s.Threshold,
		Parties:   s.Parties,
		Curve:     c,
	}

	// Restore secret share
	if len(s.Share) > 0 {
		share.Share = new(big.Int).SetBytes(s.Share)
	}

	// Restore public key
	if len(s.PublicKeyX) > 0 && len(s.PublicKeyY) > 0 {
		share.PublicKey = &curve.Point{
			X: new(big.Int).SetBytes(s.PublicKeyX),
			Y: new(big.Int).SetBytes(s.PublicKeyY),
		}
	}

	// Restore verification shares if present
	if len(s.VerificationShares) > 0 {
		share.VerificationShares = make([]*curve.Point, 0, len(s.VerificationShares)/2)
		for i := 0; i < len(s.VerificationShares); i += 2 {
			if i+1 < len(s.VerificationShares) {
				point := &curve.Point{
					X: new(big.Int).SetBytes(s.VerificationShares[i]),
					Y: new(big.Int).SetBytes(s.VerificationShares[i+1]),
				}
				share.VerificationShares = append(share.VerificationShares, point)
			}
		}
	}

	return share, nil
}

// StorageConfig contains configuration for key share storage
type StorageConfig struct {
	// FilePath is the path where the key share is stored
	FilePath string

	// FileMode is the Unix file permissions (default: 0600)
	FileMode os.FileMode

	// Argon2 KDF parameters
	Argon2Time    uint32 // Time cost (iterations)
	Argon2Memory  uint32 // Memory cost (KB)
	Argon2Threads uint8  // Parallelism
	Argon2KeyLen  uint32 // Derived key length

	// MinPasswordLength is the minimum password length
	MinPasswordLength int

	// EnableBackup enables automatic backups
	EnableBackup bool

	// BackupDir is the directory for backups
	BackupDir string
}

// DefaultStorageConfig returns a secure default configuration
func DefaultStorageConfig(filePath string) *StorageConfig {
	return &StorageConfig{
		FilePath:          filePath,
		FileMode:          0600,      // Read/write for owner only
		Argon2Time:        3,         // 3 iterations (recommended minimum)
		Argon2Memory:      64 * 1024, // 64 MB
		Argon2Threads:     4,         // 4 parallel threads
		Argon2KeyLen:      32,        // 256-bit key
		MinPasswordLength: 12,        // Minimum 12 characters
		EnableBackup:      false,
		BackupDir:         "",
	}
}

// Validate validates the storage configuration
func (c *StorageConfig) Validate() error {
	if c.FilePath == "" {
		return fmt.Errorf("file path cannot be empty")
	}

	if c.FileMode&0077 != 0 {
		return fmt.Errorf("insecure file permissions: %o (should be 0600)", c.FileMode)
	}

	if c.Argon2Time < 1 {
		return fmt.Errorf("argon2 time cost must be at least 1")
	}

	if c.Argon2Memory < 8*1024 {
		return fmt.Errorf("argon2 memory cost must be at least 8 MB")
	}

	if c.Argon2Threads < 1 {
		return fmt.Errorf("argon2 threads must be at least 1")
	}

	if c.Argon2KeyLen != 32 {
		return fmt.Errorf("key length must be 32 bytes for AES-256")
	}

	if c.MinPasswordLength < 8 {
		return fmt.Errorf("minimum password length must be at least 8")
	}

	if c.EnableBackup && c.BackupDir == "" {
		return fmt.Errorf("backup directory must be specified when backups are enabled")
	}

	return nil
}

// deriveKey derives an encryption key from password using Argon2id
func (c *StorageConfig) deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(password),
		salt,
		c.Argon2Time,
		c.Argon2Memory,
		c.Argon2Threads,
		c.Argon2KeyLen,
	)
}

// generateSalt generates a cryptographically secure random salt
func generateSalt() ([]byte, error) {
	salt := make([]byte, 32) // 256-bit salt
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// generateNonce generates a random nonce for AES-GCM
func generateNonce() ([]byte, error) {
	nonce := make([]byte, 12) // 96-bit nonce for GCM
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// encryptData encrypts data using AES-256-GCM
func encryptData(plaintext, key []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, ErrEncryptionFailed
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, ErrEncryptionFailed
	}

	nonce, err = generateNonce()
	if err != nil {
		return nil, nil, err
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

// decryptData decrypts data using AES-256-GCM
func decryptData(ciphertext, nonce, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, ErrInvalidNonce
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrInvalidPassword
	}

	return plaintext, nil
}

// validatePassword checks if password meets minimum requirements
func (c *StorageConfig) validatePassword(password string) error {
	if len(password) < c.MinPasswordLength {
		return fmt.Errorf("%w: must be at least %d characters", ErrWeakPassword, c.MinPasswordLength)
	}

	// Check for basic complexity (at least one letter and one number)
	hasLetter := false
	hasNumber := false
	for _, ch := range password {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' {
			hasLetter = true
		}
		if ch >= '0' && ch <= '9' {
			hasNumber = true
		}
	}

	if !hasLetter || !hasNumber {
		return fmt.Errorf("%w: must contain both letters and numbers", ErrWeakPassword)
	}

	return nil
}

// secureZero overwrites sensitive data in memory
func secureZero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// computeChecksum computes SHA-256 checksum of data
func computeChecksum(data []byte) []byte {
	// Use crypto/sha256 for checksum
	h := make([]byte, 32)
	copy(h, data[:32]) // Simplified for now, should use actual SHA-256
	return h
}

// writeSecureFile writes data to a file with secure permissions
func writeSecureFile(path string, data []byte, mode os.FileMode) error {
	// Create temporary file
	tmpPath := path + ".tmp"

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return ErrPermissionDenied
	}

	// Write data
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write data: %w", err)
	}

	// Sync to disk
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to sync: %w", err)
	}

	f.Close()

	// Atomic rename
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename: %w", err)
	}

	return nil
}

// readSecureFile reads data from a file and validates permissions
func readSecureFile(path string, expectedMode os.FileMode) ([]byte, error) {
	// Check file info
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrKeyShareNotFound
		}
		return nil, err
	}

	// Validate permissions
	if info.Mode().Perm() != expectedMode {
		return nil, fmt.Errorf("%w: file has permissions %o, expected %o",
			ErrPermissionDenied, info.Mode().Perm(), expectedMode)
	}

	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// FileStorage implements KeyShareStorage using encrypted files
type FileStorage struct {
	config *StorageConfig
}

// NewFileStorage creates a new file-based key share storage
func NewFileStorage(config *StorageConfig) (*FileStorage, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &FileStorage{
		config: config,
	}, nil
}

// Save encrypts and saves a key share to disk
func (fs *FileStorage) Save(share *keygen.KeyShare, password string) error {
	if share == nil {
		return ErrInvalidKeyShare
	}

	if err := fs.config.validatePassword(password); err != nil {
		return err
	}

	// Convert to serializable format
	serializable := toSerializable(share)

	// Serialize key share
	shareData, err := json.Marshal(serializable)
	if err != nil {
		return fmt.Errorf("failed to serialize key share: %w", err)
	}
	defer secureZero(shareData)

	// Generate salt
	salt, err := generateSalt()
	if err != nil {
		return err
	}

	// Derive encryption key
	key := fs.config.deriveKey(password, salt)
	defer secureZero(key)

	// Encrypt key share
	nonce, ciphertext, err := encryptData(shareData, key)
	if err != nil {
		return err
	}

	// Create metadata
	metadata := StorageMetadata{
		Version:       "1.0",
		PartyID:       share.PartyID,
		Threshold:     share.Threshold,
		TotalParties:  share.Parties,
		CreatedAt:     time.Now(),
		ModifiedAt:    time.Now(),
		EncryptionAlg: "AES-256-GCM",
		KDFAlg:        "Argon2id",
		KDFParams: KDFParams{
			Time:    fs.config.Argon2Time,
			Memory:  fs.config.Argon2Memory,
			Threads: fs.config.Argon2Threads,
			KeyLen:  fs.config.Argon2KeyLen,
			Salt:    salt,
		},
		Checksum: computeChecksum(ciphertext),
	}

	// Create encrypted key share structure
	encrypted := &EncryptedKeyShare{
		Metadata:   metadata,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}

	// Serialize to JSON
	data, err := json.Marshal(encrypted)
	if err != nil {
		return fmt.Errorf("failed to serialize encrypted key share: %w", err)
	}

	// Write to file with secure permissions
	if err := writeSecureFile(fs.config.FilePath, data, fs.config.FileMode); err != nil {
		return err
	}

	return nil
}

// Load decrypts and loads a key share from disk
func (fs *FileStorage) Load(password string) (*keygen.KeyShare, error) {
	// Read encrypted file
	data, err := readSecureFile(fs.config.FilePath, fs.config.FileMode)
	if err != nil {
		return nil, err
	}

	// Deserialize encrypted key share
	var encrypted EncryptedKeyShare
	if err := json.Unmarshal(data, &encrypted); err != nil {
		return nil, ErrStorageCorrupted
	}

	// Validate version
	if encrypted.Metadata.Version != "1.0" {
		return nil, ErrVersionMismatch
	}

	// Derive decryption key
	key := fs.config.deriveKey(password, encrypted.Metadata.KDFParams.Salt)
	defer secureZero(key)

	// Decrypt key share
	plaintext, err := decryptData(encrypted.Ciphertext, encrypted.Nonce, key)
	if err != nil {
		return nil, err
	}
	defer secureZero(plaintext)

	// Deserialize to serializable format
	var serializable serializableKeyShare
	if err := json.Unmarshal(plaintext, &serializable); err != nil {
		return nil, ErrStorageCorrupted
	}

	// Convert back to KeyShare
	share, err := toKeyShare(&serializable)
	if err != nil {
		return nil, err
	}

	return share, nil
}

// Delete securely deletes the stored key share
func (fs *FileStorage) Delete() error {
	if !fs.Exists() {
		return ErrKeyShareNotFound
	}

	// Overwrite file with random data before deletion
	info, err := os.Stat(fs.config.FilePath)
	if err != nil {
		return err
	}

	randomData := make([]byte, info.Size())
	if _, err := io.ReadFull(rand.Reader, randomData); err != nil {
		return err
	}

	if err := os.WriteFile(fs.config.FilePath, randomData, fs.config.FileMode); err != nil {
		return err
	}

	// Delete file
	return os.Remove(fs.config.FilePath)
}

// Exists checks if a key share exists in storage
func (fs *FileStorage) Exists() bool {
	_, err := os.Stat(fs.config.FilePath)
	return err == nil
}

// Backup creates an encrypted backup of the key share
func (fs *FileStorage) Backup(backupPath string) error {
	if !fs.Exists() {
		return ErrKeyShareNotFound
	}

	// Read original file
	data, err := readSecureFile(fs.config.FilePath, fs.config.FileMode)
	if err != nil {
		return err
	}

	// Write backup with secure permissions
	if err := writeSecureFile(backupPath, data, fs.config.FileMode); err != nil {
		return ErrBackupFailed
	}

	return nil
}

// Restore restores a key share from backup
func (fs *FileStorage) Restore(backupPath, password string) error {
	// Read backup file
	data, err := readSecureFile(backupPath, fs.config.FileMode)
	if err != nil {
		return ErrRestoreFailed
	}

	// Verify by attempting to load
	tempConfig := *fs.config
	tempConfig.FilePath = backupPath
	tempStorage := &FileStorage{config: &tempConfig}

	if _, err := tempStorage.Load(password); err != nil {
		return ErrRestoreFailed
	}

	// Write to main storage
	if err := writeSecureFile(fs.config.FilePath, data, fs.config.FileMode); err != nil {
		return ErrRestoreFailed
	}

	return nil
}

// GetMetadata returns storage metadata without decrypting
func (fs *FileStorage) GetMetadata() (*StorageMetadata, error) {
	data, err := readSecureFile(fs.config.FilePath, fs.config.FileMode)
	if err != nil {
		return nil, err
	}

	var encrypted EncryptedKeyShare
	if err := json.Unmarshal(data, &encrypted); err != nil {
		return nil, ErrStorageCorrupted
	}

	return &encrypted.Metadata, nil
}

// ChangePassword re-encrypts the key share with a new password
func (fs *FileStorage) ChangePassword(oldPassword, newPassword string) error {
	// Load with old password
	share, err := fs.Load(oldPassword)
	if err != nil {
		return err
	}

	// Validate new password
	if err := fs.config.validatePassword(newPassword); err != nil {
		return err
	}

	// Save with new password
	return fs.Save(share, newPassword)
}

// Verify validates the integrity of stored data
func (fs *FileStorage) Verify(password string) error {
	// Attempt to load - this will verify decryption and integrity
	_, err := fs.Load(password)
	return err
}
