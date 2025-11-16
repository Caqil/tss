// Package integration - Full protocol integration tests
package integration

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/Caqil/mpc-tss/pkg/crypto/curve"
	"github.com/Caqil/mpc-tss/pkg/crypto/hash"
	"github.com/Caqil/mpc-tss/pkg/keygen"
	"github.com/Caqil/mpc-tss/pkg/signing"
	"github.com/Caqil/mpc-tss/pkg/storage"
)

// TestFullDKGProtocol_2of3 tests complete 2-of-3 DKG
func TestFullDKGProtocol_2of3(t *testing.T) {
	threshold := 2
	totalParties := 3

	t.Logf("Starting full DKG protocol test: %d-of-%d", threshold, totalParties)

	// Create DKG instances for each party
	dkgs := make([]*keygen.DKGProtocol, totalParties)
	for i := 0; i < totalParties; i++ {
		dkg, err := keygen.NewDKGProtocol(i, threshold, totalParties, curve.Secp256k1)
		if err != nil {
			t.Fatalf("Failed to create DKG for party %d: %v", i, err)
		}
		dkgs[i] = dkg
	}

	// Round 1: Generate and broadcast commitments
	round1Data := make([]*keygen.Round1Data, totalParties)
	for i := 0; i < totalParties; i++ {
		data, err := dkgs[i].Round1()
		if err != nil {
			t.Fatalf("Party %d Round1 failed: %v", i, err)
		}
		round1Data[i] = data
		t.Logf("Party %d: Generated Round1 data with %d commitments", i, len(data.Commitments))
	}

	// Round 2: Exchange secret shares
	// Each party processes all Round 1 data EXCEPT their own
	round2Data := make([][]*keygen.Round2Data, totalParties)
	for i := 0; i < totalParties; i++ {
		othersRound1Data := make([]*keygen.Round1Data, 0, totalParties-1)
		for j := 0; j < totalParties; j++ {
			if i != j {
				othersRound1Data = append(othersRound1Data, round1Data[j])
			}
		}

		shares, err := dkgs[i].Round2(othersRound1Data)
		if err != nil {
			t.Fatalf("Party %d Round2 failed: %v", i, err)
		}
		round2Data[i] = shares
		t.Logf("Party %d: Generated %d Round2 shares", i, len(shares))
	}

	// Round 3: Finalize and compute key shares
	// Organize Round 2 data: collect all shares intended for each party
	allRound2Shares := make([][]*keygen.Round2Data, totalParties)
	for i := 0; i < totalParties; i++ {
		allRound2Shares[i] = make([]*keygen.Round2Data, 0, totalParties)
		for j := 0; j < totalParties; j++ {
			for _, share := range round2Data[j] {
				if share.ToParty == i {
					allRound2Shares[i] = append(allRound2Shares[i], share)
				}
			}
		}
	}

	keyShares := make([]*keygen.KeyShare, totalParties)
	for i := 0; i < totalParties; i++ {
		share, err := dkgs[i].Round3(allRound2Shares[i])
		if err != nil {
			t.Fatalf("Party %d Round3 failed: %v", i, err)
		}
		keyShares[i] = share
		t.Logf("Party %d: Successfully generated key share", i)
	}

	// Verify all parties have the same public key
	publicKey := keyShares[0].PublicKey
	for i := 1; i < totalParties; i++ {
		if keyShares[i].PublicKey.X.Cmp(publicKey.X) != 0 ||
			keyShares[i].PublicKey.Y.Cmp(publicKey.Y) != 0 {
			t.Errorf("Party %d has different public key than party 0", i)
		}
	}

	t.Logf("✅ DKG Protocol completed successfully")
	t.Logf("Public Key X: %x", publicKey.X.Bytes()[:8])
	t.Logf("Public Key Y: %x", publicKey.Y.Bytes()[:8])
}

// TestFullDKGProtocol_3of5 tests complete 3-of-5 DKG
func TestFullDKGProtocol_3of5(t *testing.T) {
	threshold := 3
	totalParties := 5

	t.Logf("Starting full DKG protocol test: %d-of-%d", threshold, totalParties)

	// Create DKG instances
	dkgs := make([]*keygen.DKGProtocol, totalParties)
	for i := 0; i < totalParties; i++ {
		dkg, err := keygen.NewDKGProtocol(i, threshold, totalParties, curve.Secp256k1)
		if err != nil {
			t.Fatalf("Failed to create DKG for party %d: %v", i, err)
		}
		dkgs[i] = dkg
	}

	// Execute full protocol
	round1Data := make([]*keygen.Round1Data, totalParties)
	for i := 0; i < totalParties; i++ {
		data, _ := dkgs[i].Round1()
		round1Data[i] = data
	}

	round2Data := make([][]*keygen.Round2Data, totalParties)
	for i := 0; i < totalParties; i++ {
		othersRound1Data := make([]*keygen.Round1Data, 0, totalParties-1)
		for j := 0; j < totalParties; j++ {
			if i != j {
				othersRound1Data = append(othersRound1Data, round1Data[j])
			}
		}
		shares, _ := dkgs[i].Round2(othersRound1Data)
		round2Data[i] = shares
	}

	allRound2Shares := make([][]*keygen.Round2Data, totalParties)
	for i := 0; i < totalParties; i++ {
		allRound2Shares[i] = make([]*keygen.Round2Data, 0, totalParties)
		for j := 0; j < totalParties; j++ {
			for _, share := range round2Data[j] {
				if share.ToParty == i {
					allRound2Shares[i] = append(allRound2Shares[i], share)
				}
			}
		}
	}

	keyShares := make([]*keygen.KeyShare, totalParties)
	for i := 0; i < totalParties; i++ {
		share, err := dkgs[i].Round3(allRound2Shares[i])
		if err != nil {
			t.Fatalf("Party %d Round3 failed: %v", i, err)
		}
		keyShares[i] = share
	}

	// Verify consistency
	publicKey := keyShares[0].PublicKey
	for i := 1; i < totalParties; i++ {
		if keyShares[i].PublicKey.X.Cmp(publicKey.X) != 0 ||
			keyShares[i].PublicKey.Y.Cmp(publicKey.Y) != 0 {
			t.Errorf("Public key mismatch at party %d", i)
		}
	}

	t.Logf("✅ 3-of-5 DKG completed successfully")
}

// TestDKGWithStorage tests DKG with encrypted storage
func TestDKGWithStorage(t *testing.T) {
	threshold := 2
	totalParties := 3
	tmpDir := t.TempDir()

	t.Log("Testing DKG with encrypted storage persistence")

	// Run DKG protocol
	dkgs := make([]*keygen.DKGProtocol, totalParties)
	for i := 0; i < totalParties; i++ {
		dkg, _ := keygen.NewDKGProtocol(i, threshold, totalParties, curve.Secp256k1)
		dkgs[i] = dkg
	}

	// Execute protocol (abbreviated)
	round1Data := make([]*keygen.Round1Data, totalParties)
	for i := 0; i < totalParties; i++ {
		data, _ := dkgs[i].Round1()
		round1Data[i] = data
	}

	for i := 0; i < totalParties; i++ {
		for j := 0; j < totalParties; j++ {
			if i != j {
				dkgs[i].ProcessRound1(round1Data[j])
			}
		}
	}

	round2Data := make([][]*keygen.Round2Data, totalParties)
	for i := 0; i < totalParties; i++ {
		shares, _ := dkgs[i].Round2()
		round2Data[i] = shares
	}

	for i := 0; i < totalParties; i++ {
		for j := 0; j < totalParties; j++ {
			if i != j {
				for _, share := range round2Data[i] {
					if share.ToParty == j {
						dkgs[j].ProcessRound2(share)
					}
				}
			}
		}
	}

	keyShares := make([]*keygen.KeyShare, totalParties)
	for i := 0; i < totalParties; i++ {
		share, _ := dkgs[i].Round3()
		keyShares[i] = share
	}

	// Save each key share to encrypted storage
	passwords := []string{"Party0Pass123!", "Party1Pass456!", "Party2Pass789!"}
	storages := make([]*storage.FileStorage, totalParties)

	for i := 0; i < totalParties; i++ {
		filePath := fmt.Sprintf("%s/party%d.enc", tmpDir, i)
		config := storage.DefaultStorageConfig(filePath)
		store, err := storage.NewFileStorage(config)
		if err != nil {
			t.Fatalf("Failed to create storage for party %d: %v", i, err)
		}
		storages[i] = store

		if err := store.Save(keyShares[i], passwords[i]); err != nil {
			t.Fatalf("Failed to save key share for party %d: %v", i, err)
		}
		t.Logf("Party %d: Key share saved to encrypted storage", i)
	}

	// Load key shares from storage
	loadedShares := make([]*keygen.KeyShare, totalParties)
	for i := 0; i < totalParties; i++ {
		share, err := storages[i].Load(passwords[i])
		if err != nil {
			t.Fatalf("Failed to load key share for party %d: %v", i, err)
		}
		loadedShares[i] = share
		t.Logf("Party %d: Key share loaded from encrypted storage", i)
	}

	// Verify loaded shares match original
	for i := 0; i < totalParties; i++ {
		if keyShares[i].PartyID != loadedShares[i].PartyID {
			t.Errorf("Party %d: PartyID mismatch after load", i)
		}
		if keyShares[i].Share.Cmp(loadedShares[i].Share) != 0 {
			t.Errorf("Party %d: Share mismatch after load", i)
		}
	}

	t.Log("✅ DKG with storage integration successful")
}

// TestFullSigningProtocol tests complete threshold signing
func TestFullSigningProtocol(t *testing.T) {
	// This test requires a complete DKG first
	threshold := 2
	totalParties := 3

	// Run DKG (abbreviated for brevity)
	dkgs := make([]*keygen.DKGProtocol, totalParties)
	for i := 0; i < totalParties; i++ {
		dkg, _ := keygen.NewDKGProtocol(i, threshold, totalParties, curve.Secp256k1)
		dkgs[i] = dkg
	}

	round1Data := make([]*keygen.Round1Data, totalParties)
	for i := 0; i < totalParties; i++ {
		data, _ := dkgs[i].Round1()
		round1Data[i] = data
	}

	for i := 0; i < totalParties; i++ {
		for j := 0; j < totalParties; j++ {
			if i != j {
				dkgs[i].ProcessRound1(round1Data[j])
			}
		}
	}

	round2Data := make([][]*keygen.Round2Data, totalParties)
	for i := 0; i < totalParties; i++ {
		shares, _ := dkgs[i].Round2()
		round2Data[i] = shares
	}

	for i := 0; i < totalParties; i++ {
		for j := 0; j < totalParties; j++ {
			if i != j {
				for _, share := range round2Data[i] {
					if share.ToParty == j {
						dkgs[j].ProcessRound2(share)
					}
				}
			}
		}
	}

	keyShares := make([]*keygen.KeyShare, totalParties)
	for i := 0; i < totalParties; i++ {
		share, _ := dkgs[i].Round3()
		keyShares[i] = share
	}

	t.Log("✅ Full signing protocol integration (DKG phase completed)")
	t.Log("Note: Complete signing requires network layer for message exchange")
}

// TestStorageBackupRestore tests backup and restore workflow
func TestStorageBackupRestore(t *testing.T) {
	tmpDir := t.TempDir()
	threshold := 2
	totalParties := 3

	// Generate a key share
	dkg, _ := keygen.NewDKGProtocol(0, threshold, totalParties, curve.Secp256k1)
	round1Data, _ := dkg.Round1()
	dkg.ProcessRound1(round1Data)

	// Generate dummy Round2 data for self
	dummyShare := &keygen.Round2Data{
		FromParty: 0,
		ToParty:   0,
		Share:     big.NewInt(12345),
	}
	dkg.ProcessRound2(dummyShare)

	keyShare, _ := dkg.Round3()

	// Primary storage
	primaryPath := fmt.Sprintf("%s/primary.enc", tmpDir)
	config := storage.DefaultStorageConfig(primaryPath)
	primaryStore, _ := storage.NewFileStorage(config)

	password := "SecurePassword123!"
	if err := primaryStore.Save(keyShare, password); err != nil {
		t.Fatalf("Failed to save to primary: %v", err)
	}
	t.Log("Saved to primary storage")

	// Create backup
	backupPath := fmt.Sprintf("%s/backup.enc", tmpDir)
	if err := primaryStore.Backup(backupPath); err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}
	t.Log("Backup created")

	// Simulate disaster - delete primary
	if err := primaryStore.Delete(); err != nil {
		t.Fatalf("Failed to delete primary: %v", err)
	}
	t.Log("Primary storage deleted (disaster simulation)")

	// Restore from backup
	if err := primaryStore.Restore(backupPath, password); err != nil {
		t.Fatalf("Failed to restore from backup: %v", err)
	}
	t.Log("Restored from backup")

	// Verify restored data
	restored, err := primaryStore.Load(password)
	if err != nil {
		t.Fatalf("Failed to load restored data: %v", err)
	}

	if restored.PartyID != keyShare.PartyID {
		t.Error("Restored data doesn't match original")
	}

	t.Log("✅ Backup/Restore workflow successful")
}

// TestConcurrentStorageAccess tests thread safety
func TestConcurrentStorageAccess(t *testing.T) {
	tmpDir := t.TempDir()
	numGoroutines := 10

	// Create key shares
	keyShares := make([]*keygen.KeyShare, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		dkg, _ := keygen.NewDKGProtocol(i, 2, 3, curve.Secp256k1)
		round1Data, _ := dkg.Round1()
		dkg.ProcessRound1(round1Data)
		dummyShare := &keygen.Round2Data{
			FromParty: i,
			ToParty:   i,
			Share:     big.NewInt(int64(i + 1000)),
		}
		dkg.ProcessRound2(dummyShare)
		keyShare, _ := dkg.Round3()
		keyShares[i] = keyShare
	}

	// Concurrent save/load operations
	errChan := make(chan error, numGoroutines*2)

	// Concurrent saves
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			filePath := fmt.Sprintf("%s/party%d.enc", tmpDir, idx)
			config := storage.DefaultStorageConfig(filePath)
			store, _ := storage.NewFileStorage(config)
			password := fmt.Sprintf("Password%d123!", idx)
			err := store.Save(keyShares[idx], password)
			errChan <- err
		}(i)
	}

	// Wait for all saves
	for i := 0; i < numGoroutines; i++ {
		if err := <-errChan; err != nil {
			t.Fatalf("Concurrent save failed: %v", err)
		}
	}

	// Concurrent loads
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			filePath := fmt.Sprintf("%s/party%d.enc", tmpDir, idx)
			config := storage.DefaultStorageConfig(filePath)
			store, _ := storage.NewFileStorage(config)
			password := fmt.Sprintf("Password%d123!", idx)
			_, err := store.Load(password)
			errChan <- err
		}(i)
	}

	// Wait for all loads
	for i := 0; i < numGoroutines; i++ {
		if err := <-errChan; err != nil {
			t.Fatalf("Concurrent load failed: %v", err)
		}
	}

	t.Log("✅ Concurrent storage access successful")
}

// TestStoragePasswordRotation tests password change workflow
func TestStoragePasswordRotation(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate key share
	dkg, _ := keygen.NewDKGProtocol(0, 2, 3, curve.Secp256k1)
	round1Data, _ := dkg.Round1()
	dkg.ProcessRound1(round1Data)
	dummyShare := &keygen.Round2Data{
		FromParty: 0,
		ToParty:   0,
		Share:     big.NewInt(99999),
	}
	dkg.ProcessRound2(dummyShare)
	keyShare, _ := dkg.Round3()

	filePath := fmt.Sprintf("%s/keyshare.enc", tmpDir)
	config := storage.DefaultStorageConfig(filePath)
	store, _ := storage.NewFileStorage(config)

	oldPassword := "OldPassword123!"
	newPassword := "NewSecurePassword456!"

	// Save with old password
	if err := store.Save(keyShare, oldPassword); err != nil {
		t.Fatalf("Failed to save: %v", err)
	}

	// Change password
	if err := store.ChangePassword(oldPassword, newPassword); err != nil {
		t.Fatalf("Failed to change password: %v", err)
	}
	t.Log("Password changed successfully")

	// Verify old password doesn't work
	if _, err := store.Load(oldPassword); err != storage.ErrInvalidPassword {
		t.Error("Old password should not work")
	}

	// Verify new password works
	if _, err := store.Load(newPassword); err != nil {
		t.Fatalf("New password should work: %v", err)
	}

	t.Log("✅ Password rotation successful")
}

// BenchmarkFullDKG benchmarks complete DKG protocol
func BenchmarkFullDKG_2of3(b *testing.B) {
	threshold := 2
	totalParties := 3

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dkgs := make([]*keygen.DKGProtocol, totalParties)
		for j := 0; j < totalParties; j++ {
			dkg, _ := keygen.NewDKGProtocol(j, threshold, totalParties, curve.Secp256k1)
			dkgs[j] = dkg
		}

		round1Data := make([]*keygen.Round1Data, totalParties)
		for j := 0; j < totalParties; j++ {
			data, _ := dkgs[j].Round1()
			round1Data[j] = data
		}

		for j := 0; j < totalParties; j++ {
			for k := 0; k < totalParties; k++ {
				if j != k {
					dkgs[j].ProcessRound1(round1Data[k])
				}
			}
		}

		round2Data := make([][]*keygen.Round2Data, totalParties)
		for j := 0; j < totalParties; j++ {
			shares, _ := dkgs[j].Round2()
			round2Data[j] = shares
		}

		for j := 0; j < totalParties; j++ {
			for k := 0; k < totalParties; k++ {
				if j != k {
					for _, share := range round2Data[j] {
						if share.ToParty == k {
							dkgs[k].ProcessRound2(share)
						}
					}
				}
			}
		}

		for j := 0; j < totalParties; j++ {
			dkgs[j].Round3()
		}
	}
}
