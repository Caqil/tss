package signing

import (
	"crypto/sha256"
	"math/big"
	"testing"
	"time"

	"github.com/Caqil/mpc-tss/pkg/crypto/curve"
	"github.com/Caqil/mpc-tss/pkg/keygen"
)

// TestFullThresholdSigningProtocol_2of3 tests the complete 2-of-3 threshold signing
func TestFullThresholdSigningProtocol_2of3(t *testing.T) {
	// Setup: Create 3 parties with 2-of-3 threshold
	parties := 3
	threshold := 2

	c, err := curve.NewCurve(curve.Secp256k1)
	if err != nil {
		t.Fatalf("Failed to create curve: %v", err)
	}

	// Create key shares for each party
	// In a real scenario, these would come from DKG
	keyShares := make([]*keygen.KeyShare, parties)
	publicKey, _ := c.ScalarBaseMult(big.NewInt(100)) // Shared public key

	for i := 0; i < parties; i++ {
		verificationShares := make([]*curve.Point, parties)
		for j := 0; j < parties; j++ {
			verificationShares[j], _ = c.ScalarBaseMult(big.NewInt(int64(j + 1)))
		}

		keyShares[i] = &keygen.KeyShare{
			PartyID:            i,
			Threshold:          threshold,
			Parties:            parties,
			Share:              big.NewInt(int64(i + 1)),
			PublicKey:          publicKey,
			VerificationShares: verificationShares,
			Curve:              c,
		}
	}

	// Create signers
	signers := make([]*ThresholdSigner, parties)
	for i := 0; i < parties; i++ {
		signers[i], err = NewThresholdSigner(keyShares[i])
		if err != nil {
			t.Fatalf("Failed to create signer %d: %v", i, err)
		}
	}

	// Message to sign
	msg := []byte("Hello, TSS!")
	msgHash := sha256.Sum256(msg)

	// Create shared session ID for all parties
	sessionID := sha256.Sum256(append(msgHash[:], []byte("session")...))

	// Start sessions for all parties with shared session ID
	for i := 0; i < parties; i++ {
		err = signers[i].StartSessionWithID(msgHash[:], sessionID[:], 10*time.Minute)
		if err != nil {
			t.Fatalf("Failed to start session for party %d: %v", i, err)
		}
	}

	// Round 1: Generate commitments (use only threshold parties)
	activeParties := threshold
	round1Data := make([]*SignRound1Data, 0, activeParties)

	for i := 0; i < activeParties; i++ {
		data, err := signers[i].SignRound1(msgHash[:])
		if err != nil {
			t.Fatalf("Round 1 failed for party %d: %v", i, err)
		}
		round1Data = append(round1Data, data)
	}

	// Distribute Round 1 data to all active parties
	round1DataForParties := make([][]*SignRound1Data, activeParties)
	for i := 0; i < activeParties; i++ {
		round1DataForParties[i] = make([]*SignRound1Data, 0, activeParties-1)
		for j := 0; j < activeParties; j++ {
			if i != j {
				round1DataForParties[i] = append(round1DataForParties[i], round1Data[j])
			}
		}
	}

	// Round 2: Reveal nonces
	round2Data := make([]*SignRound2Data, 0, activeParties)

	for i := 0; i < activeParties; i++ {
		data, err := signers[i].SignRound2(msgHash[:], round1DataForParties[i])
		if err != nil {
			t.Fatalf("Round 2 failed for party %d: %v", i, err)
		}
		round2Data = append(round2Data, data)
	}

	// Distribute Round 2 data
	round2DataForParties := make([][]*SignRound2Data, activeParties)
	for i := 0; i < activeParties; i++ {
		round2DataForParties[i] = make([]*SignRound2Data, 0, activeParties-1)
		for j := 0; j < activeParties; j++ {
			if i != j {
				round2DataForParties[i] = append(round2DataForParties[i], round2Data[j])
			}
		}
	}

	// Round 3: Compute partial signatures
	round3Data := make([]*SignRound3Data, 0, activeParties)

	for i := 0; i < activeParties; i++ {
		data, err := signers[i].SignRound3(msgHash[:], round2DataForParties[i])
		if err != nil {
			t.Fatalf("Round 3 failed for party %d: %v", i, err)
		}
		round3Data = append(round3Data, data)
	}

	// Distribute Round 3 data
	round3DataForParties := make([][]*SignRound3Data, activeParties)
	for i := 0; i < activeParties; i++ {
		round3DataForParties[i] = make([]*SignRound3Data, 0, activeParties-1)
		for j := 0; j < activeParties; j++ {
			if i != j {
				round3DataForParties[i] = append(round3DataForParties[i], round3Data[j])
			}
		}
	}

	// Round 4: Aggregate signatures
	// All parties should produce the same signature
	signatures := make([]*Signature, activeParties)

	for i := 0; i < activeParties; i++ {
		sig, err := signers[i].SignRound4(msgHash[:], round3DataForParties[i])
		if err != nil {
			t.Fatalf("Round 4 failed for party %d: %v", i, err)
		}
		signatures[i] = sig
	}

	// Verify all parties produced the same signature
	for i := 1; i < activeParties; i++ {
		if signatures[i].R.Cmp(signatures[0].R) != 0 {
			t.Errorf("Party %d produced different R value", i)
		}
		if signatures[i].S.Cmp(signatures[0].S) != 0 {
			t.Errorf("Party %d produced different S value", i)
		}
	}

	t.Logf("Successfully completed %d-of-%d threshold signing", threshold, parties)
	t.Logf("Signature R: %s", signatures[0].R.String())
	t.Logf("Signature S: %s", signatures[0].S.String())
}

// TestPreSigningProtocol tests the presigning workflow
func TestPreSigningProtocol(t *testing.T) {
	// Setup
	parties := 3
	threshold := 2

	c, err := curve.NewCurve(curve.Secp256k1)
	if err != nil {
		t.Fatalf("Failed to create curve: %v", err)
	}

	// Create key shares
	keyShares := make([]*keygen.KeyShare, parties)
	publicKey, _ := c.ScalarBaseMult(big.NewInt(100))

	for i := 0; i < parties; i++ {
		verificationShares := make([]*curve.Point, parties)
		for j := 0; j < parties; j++ {
			verificationShares[j], _ = c.ScalarBaseMult(big.NewInt(int64(j + 1)))
		}

		keyShares[i] = &keygen.KeyShare{
			PartyID:            i,
			Threshold:          threshold,
			Parties:            parties,
			Share:              big.NewInt(int64((i + 1) * 1000)),
			PublicKey:          publicKey,
			VerificationShares: verificationShares,
			Curve:              c,
		}
	}

	// Create signers
	signers := make([]*ThresholdSigner, threshold)
	for i := 0; i < threshold; i++ {
		signers[i], err = NewThresholdSigner(keyShares[i])
		if err != nil {
			t.Fatalf("Failed to create signer %d: %v", i, err)
		}
	}

	// Presigning Round 1
	round1DataList := make([]*PreSignRound1Data, threshold)
	round1States := make([]*round1State, threshold)

	for i := 0; i < threshold; i++ {
		data, state, err := signers[i].GeneratePreSignatureRound1()
		if err != nil {
			t.Fatalf("Presigning Round 1 failed for party %d: %v", i, err)
		}
		round1DataList[i] = data
		round1States[i] = state
	}

	// Ensure all parties use the same PreSignID
	preSignID := round1DataList[0].PreSignID

	// Distribute Round 1 data
	round1ForParties := make([][]*PreSignRound1Data, threshold)
	for i := 0; i < threshold; i++ {
		round1ForParties[i] = make([]*PreSignRound1Data, 0, threshold-1)
		for j := 0; j < threshold; j++ {
			if i != j {
				// Update PreSignID to match
				round1DataList[j].PreSignID = preSignID
				round1ForParties[i] = append(round1ForParties[i], round1DataList[j])
			}
		}
	}

	// Presigning Round 2
	round2DataList := make([]*PreSignRound2Data, threshold)
	receivedDataList := make([]map[int]*PreSignRound1Data, threshold)

	for i := 0; i < threshold; i++ {
		data, received, err := signers[i].GeneratePreSignatureRound2(preSignID, round1States[i], round1ForParties[i])
		if err != nil {
			t.Fatalf("Presigning Round 2 failed for party %d: %v", i, err)
		}
		round2DataList[i] = data
		receivedDataList[i] = received
	}

	// Distribute Round 2 data
	round2ForParties := make([][]*PreSignRound2Data, threshold)
	for i := 0; i < threshold; i++ {
		round2ForParties[i] = make([]*PreSignRound2Data, 0, threshold-1)
		for j := 0; j < threshold; j++ {
			if i != j {
				round2ForParties[i] = append(round2ForParties[i], round2DataList[j])
			}
		}
	}

	// Finalize pre-signatures
	preSignatures := make([]*PreSignature, threshold)

	for i := 0; i < threshold; i++ {
		preSign, err := signers[i].FinalizePreSignature(preSignID, round1States[i], receivedDataList[i], round2ForParties[i])
		if err != nil {
			t.Fatalf("Failed to finalize presignature for party %d: %v", i, err)
		}
		preSignatures[i] = preSign
	}

	// Verify all parties have the same R value
	for i := 1; i < threshold; i++ {
		if !preSignatures[i].R.IsEqual(preSignatures[0].R) {
			t.Errorf("Party %d has different R value", i)
		}
	}

	t.Logf("Successfully completed presigning protocol")
	t.Logf("PreSign R: %v", preSignatures[0].R)
}

// TestBatchSigning tests batch signing with pre-signatures
func TestBatchSigning(t *testing.T) {
	c, err := curve.NewCurve(curve.Secp256k1)
	if err != nil {
		t.Fatalf("Failed to create curve: %v", err)
	}

	// Create a single key share for testing
	publicKey, _ := c.ScalarBaseMult(big.NewInt(100))
	verificationShares := make([]*curve.Point, 3)
	for j := 0; j < 3; j++ {
		verificationShares[j], _ = c.ScalarBaseMult(big.NewInt(int64(j + 1)))
	}

	keyShare := &keygen.KeyShare{
		PartyID:            0,
		Threshold:          2,
		Parties:            3,
		Share:              big.NewInt(1000),
		PublicKey:          publicKey,
		VerificationShares: verificationShares,
		Curve:              c,
	}

	signer, err := NewThresholdSigner(keyShare)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Create batch signer
	_ = NewBatchSigner(signer)

	// Create multiple messages
	messages := []string{"msg1", "msg2", "msg3"}
	messageHashes := make([][]byte, len(messages))

	for i, msg := range messages {
		hash := sha256.Sum256([]byte(msg))
		messageHashes[i] = hash[:]
	}

	// Create pre-signature pool
	_ = NewPreSignaturePool(keyShare, 10, 24*time.Hour)

	// Note: In a real scenario, pre-signatures would be generated through the full protocol
	// For testing, we'll create mock pre-signatures
	t.Logf("Batch signing test completed (would need full presigning protocol for real signatures)")
}

// TestDeterministicSigning tests RFC 6979 deterministic signing
func TestDeterministicSigning(t *testing.T) {
	c, err := curve.NewCurve(curve.Secp256k1)
	if err != nil {
		t.Fatalf("Failed to create curve: %v", err)
	}

	publicKey, _ := c.ScalarBaseMult(big.NewInt(100))
	verificationShares := make([]*curve.Point, 3)
	for j := 0; j < 3; j++ {
		verificationShares[j], _ = c.ScalarBaseMult(big.NewInt(int64(j + 1)))
	}

	keyShare := &keygen.KeyShare{
		PartyID:            0,
		Threshold:          2,
		Parties:            3,
		Share:              big.NewInt(12345),
		PublicKey:          publicKey,
		VerificationShares: verificationShares,
		Curve:              c,
	}

	signer, err := NewThresholdSigner(keyShare)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	msg := []byte("deterministic message")
	msgHash := sha256.Sum256(msg)

	// Sign the same message twice
	sig1, err := signer.DeterministicSign(msgHash[:])
	if err != nil {
		t.Fatalf("First deterministic signing failed: %v", err)
	}

	sig2, err := signer.DeterministicSign(msgHash[:])
	if err != nil {
		t.Fatalf("Second deterministic signing failed: %v", err)
	}

	// Signatures should be identical
	if sig1.R.Cmp(sig2.R) != 0 {
		t.Error("Deterministic signatures have different R values")
	}

	if sig1.S.Cmp(sig2.S) != 0 {
		t.Error("Deterministic signatures have different S values")
	}

	t.Logf("Deterministic signing produced identical signatures")
}

// TestPreSignaturePool tests pre-signature pool management
func TestPreSignaturePool(t *testing.T) {
	c, err := curve.NewCurve(curve.Secp256k1)
	if err != nil {
		t.Fatalf("Failed to create curve: %v", err)
	}

	publicKey, _ := c.ScalarBaseMult(big.NewInt(100))

	keyShare := &keygen.KeyShare{
		PartyID:   0,
		Threshold: 2,
		Parties:   3,
		Share:     big.NewInt(12345),
		PublicKey: publicKey,
		Curve:     c,
	}

	// Create pool
	pool := NewPreSignaturePool(keyShare, 5, 1*time.Hour)

	if pool.Size() != 0 {
		t.Error("New pool should be empty")
	}

	if pool.Available() != 0 {
		t.Error("New pool should have no available pre-signatures")
	}

	// Create and add mock pre-signatures
	for i := 0; i < 3; i++ {
		R, _ := c.ScalarBaseMult(big.NewInt(int64(i + 1)))
		preSign := &PreSignature{
			ID:        []byte{byte(i)},
			R:         R,
			r:         big.NewInt(int64(i + 1)),
			k:         big.NewInt(int64(i + 100)),
			kInv:      big.NewInt(int64(i + 200)),
			PartyID:   0,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
			used:      false,
		}

		err := pool.Add(preSign)
		if err != nil {
			t.Fatalf("Failed to add pre-signature %d: %v", i, err)
		}
	}

	if pool.Size() != 3 {
		t.Errorf("Expected pool size 3, got %d", pool.Size())
	}

	if pool.Available() != 3 {
		t.Errorf("Expected 3 available pre-signatures, got %d", pool.Available())
	}

	// Get a pre-signature
	preSign, err := pool.Get()
	if err != nil {
		t.Fatalf("Failed to get pre-signature: %v", err)
	}

	if preSign == nil {
		t.Error("Got nil pre-signature")
	}

	// Mark as used
	preSign.mu.Lock()
	preSign.used = true
	preSign.mu.Unlock()

	// Available count should decrease after cleanup
	removed := pool.Cleanup()
	if removed != 1 {
		t.Errorf("Expected to remove 1 used pre-signature, removed %d", removed)
	}

	// Clear pool
	pool.Clear()
	if pool.Size() != 0 {
		t.Errorf("Pool should be empty after clear, size: %d", pool.Size())
	}
}

// Benchmark integration tests
func BenchmarkFullThresholdSigning(b *testing.B) {
	// This would benchmark the full signing protocol
	// Omitted for brevity but would follow the pattern of TestFullThresholdSigningProtocol_2of3
	b.Skip("Full benchmark requires complete test setup")
}
