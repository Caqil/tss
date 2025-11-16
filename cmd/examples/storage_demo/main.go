// Package main demonstrates secure encrypted storage of key shares
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/Caqil/mpc-tss/pkg/crypto/curve"
	"github.com/Caqil/mpc-tss/pkg/keygen"
	"github.com/Caqil/mpc-tss/pkg/storage"
)

func main() {
	fmt.Println("=== Secure Storage Demo ===")

	// Create temporary directory for demo
	tmpDir, err := os.MkdirTemp("", "mpc-tss-storage-demo-*")
	if err != nil {
		log.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fmt.Printf("Using temporary directory: %s\n\n", tmpDir)

	// Step 1: Generate a key share (simplified)
	fmt.Println("Step 1: Generating key share...")
	keyShare := generateTestKeyShare()
	fmt.Printf("  ✓ Key share generated for Party %d\n", keyShare.PartyID)
	fmt.Printf("    Threshold: %d-of-%d\n", keyShare.Threshold, keyShare.Parties)

	// Step 2: Save with encryption
	fmt.Println("\nStep 2: Saving key share with encryption...")
	password := "MySecurePassword123!"
	filePath := filepath.Join(tmpDir, "keyshare.enc")

	config := storage.DefaultStorageConfig(filePath)
	store, err := storage.NewFileStorage(config)
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}

	if err := store.Save(keyShare, password); err != nil {
		log.Fatalf("Failed to save: %v", err)
	}
	fmt.Println("  ✓ Key share encrypted and saved")
	fmt.Printf("    File: %s\n", filePath)
	fmt.Println("    Encryption: AES-256-GCM")
	fmt.Println("    KDF: Argon2id (64MB, 3 iterations)")

	// Step 3: Get metadata (without decryption)
	fmt.Println("\nStep 3: Reading metadata (no decryption needed)...")
	metadata, err := store.GetMetadata()
	if err != nil {
		log.Fatalf("Failed to get metadata: %v", err)
	}
	fmt.Printf("  ✓ Metadata retrieved\n")
	fmt.Printf("    Party ID: %d\n", metadata.PartyID)
	fmt.Printf("    Threshold: %d/%d\n", metadata.Threshold, metadata.TotalParties)
	fmt.Printf("    Created: %s\n", metadata.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("    Encryption: %s\n", metadata.EncryptionAlg)
	fmt.Printf("    KDF: %s\n", metadata.KDFAlg)

	// Step 4: Load with password
	fmt.Println("\nStep 4: Loading key share...")
	loadedShare, err := store.Load(password)
	if err != nil {
		log.Fatalf("Failed to load: %v", err)
	}
	fmt.Println("  ✓ Key share decrypted and loaded")
	fmt.Printf("    Party ID: %d (matches: %v)\n",
		loadedShare.PartyID, loadedShare.PartyID == keyShare.PartyID)

	// Step 5: Verify integrity
	fmt.Println("\nStep 5: Verifying integrity...")
	if err := store.Verify(password); err != nil {
		log.Fatalf("Verification failed: %v", err)
	}
	fmt.Println("  ✓ Integrity verified successfully")

	// Step 6: Create backup
	fmt.Println("\nStep 6: Creating encrypted backup...")
	backupPath := filepath.Join(tmpDir, "keyshare.backup.enc")
	if err := store.Backup(backupPath); err != nil {
		log.Fatalf("Failed to create backup: %v", err)
	}
	fmt.Printf("  ✓ Backup created: %s\n", backupPath)

	// Step 7: Simulate disaster and restore
	fmt.Println("\nStep 7: Simulating disaster recovery...")
	if err := store.Delete(); err != nil {
		log.Fatalf("Failed to delete: %v", err)
	}
	fmt.Println("  ⚠ Primary storage deleted (disaster simulation)")

	if err := store.Restore(backupPath, password); err != nil {
		log.Fatalf("Failed to restore: %v", err)
	}
	fmt.Println("  ✓ Restored from backup successfully")

	// Verify restored data
	restoredShare, err := store.Load(password)
	if err != nil {
		log.Fatalf("Failed to load restored share: %v", err)
	}
	if restoredShare.PartyID != keyShare.PartyID {
		log.Fatal("Restored data doesn't match original!")
	}
	fmt.Println("  ✓ Restored data verified")

	// Step 8: Password rotation
	fmt.Println("\nStep 8: Rotating password...")
	newPassword := "NewSecurePassword456!"
	if err := store.ChangePassword(password, newPassword); err != nil {
		log.Fatalf("Failed to change password: %v", err)
	}
	fmt.Println("  ✓ Password changed successfully")

	// Verify old password doesn't work
	if _, err := store.Load(password); err != storage.ErrInvalidPassword {
		log.Fatal("Old password should not work!")
	}
	fmt.Println("  ✓ Old password rejected")

	// Verify new password works
	if _, err := store.Load(newPassword); err != nil {
		log.Fatalf("New password should work: %v", err)
	}
	fmt.Println("  ✓ New password accepted")

	// Final cleanup
	fmt.Println("\nStep 9: Secure deletion...")
	if err := store.Delete(); err != nil {
		log.Fatalf("Failed to delete: %v", err)
	}
	fmt.Println("  ✓ Key share securely deleted (overwritten)")

	fmt.Println("\n=== Storage Demo Complete! ===")
	fmt.Println("\nSecurity Features Demonstrated:")
	fmt.Println("  ✓ AES-256-GCM authenticated encryption")
	fmt.Println("  ✓ Argon2id key derivation (brute-force resistant)")
	fmt.Println("  ✓ Secure file permissions (0600)")
	fmt.Println("  ✓ Metadata access without decryption")
	fmt.Println("  ✓ Backup and restore capabilities")
	fmt.Println("  ✓ Password rotation")
	fmt.Println("  ✓ Integrity verification")
	fmt.Println("  ✓ Secure deletion with overwrite")
}

// generateTestKeyShare creates a test key share for demonstration
// Runs a complete 2-of-3 DKG protocol simulation
func generateTestKeyShare() *keygen.KeyShare {
	threshold := 2
	totalParties := 3
	myPartyID := 0

	// Create DKG instances for all parties (simulation)
	dkgs := make([]*keygen.DKGProtocol, totalParties)
	for i := 0; i < totalParties; i++ {
		dkg, err := keygen.NewDKGProtocol(i, threshold, totalParties, curve.Secp256k1)
		if err != nil {
			log.Fatalf("Failed to create DKG for party %d: %v", i, err)
		}
		dkgs[i] = dkg
	}

	// Round 1: All parties generate commitments
	round1Data := make([]*keygen.Round1Data, totalParties)
	for i := 0; i < totalParties; i++ {
		data, err := dkgs[i].Round1()
		if err != nil {
			log.Fatalf("Party %d Round1 failed: %v", i, err)
		}
		round1Data[i] = data
	}

	// Round 2: All parties generate shares
	round2Data := make([][]*keygen.Round2Data, totalParties)
	for i := 0; i < totalParties; i++ {
		shares, err := dkgs[i].Round2(round1Data)
		if err != nil {
			log.Fatalf("Party %d Round2 failed: %v", i, err)
		}
		round2Data[i] = shares
	}

	// Organize Round 2 data for our party
	myRound2Shares := make([]*keygen.Round2Data, 0, totalParties-1)
	for i := 0; i < totalParties; i++ {
		for _, share := range round2Data[i] {
			if share.ToParty == myPartyID {
				myRound2Shares = append(myRound2Shares, share)
			}
		}
	}

	// Round 3: Finalize our key share
	keyShare, err := dkgs[myPartyID].Round3(myRound2Shares)
	if err != nil {
		log.Fatalf("Round3 failed: %v", err)
	}

	return keyShare
}
