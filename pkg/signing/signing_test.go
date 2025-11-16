package signing

import (
	"crypto/sha256"
	"math/big"
	"testing"
	"time"

	"github.com/Caqil/mpc-tss/pkg/crypto/curve"
	"github.com/Caqil/mpc-tss/pkg/keygen"
)

// TestNewThresholdSigner tests signer creation
func TestNewThresholdSigner(t *testing.T) {
	c, err := curve.NewCurve(curve.Secp256k1)
	if err != nil {
		t.Fatalf("Failed to create curve: %v", err)
	}

	keyShare := &keygen.KeyShare{
		PartyID:   0,
		Threshold: 2,
		Parties:   3,
		Share:     big.NewInt(12345),
		PublicKey: &curve.Point{
			X: big.NewInt(1),
			Y: big.NewInt(2),
		},
		VerificationShares: make([]*curve.Point, 3),
		Curve:              c,
	}

	signer, err := NewThresholdSigner(keyShare)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	if signer.partyID != 0 {
		t.Errorf("Expected partyID 0, got %d", signer.partyID)
	}

	if signer.threshold != 2 {
		t.Errorf("Expected threshold 2, got %d", signer.threshold)
	}
}

// TestNewThresholdSignerInvalidKeyShare tests error handling
func TestNewThresholdSignerInvalidKeyShare(t *testing.T) {
	// Nil key share
	_, err := NewThresholdSigner(nil)
	if err != ErrInvalidKeyShare {
		t.Errorf("Expected ErrInvalidKeyShare, got %v", err)
	}

	// Nil curve
	keyShare := &keygen.KeyShare{
		PartyID:   0,
		Threshold: 2,
		Parties:   3,
		Share:     big.NewInt(12345),
	}

	_, err = NewThresholdSigner(keyShare)
	if err != ErrNilCurve {
		t.Errorf("Expected ErrNilCurve, got %v", err)
	}
}

// TestSessionManagement tests session lifecycle
func TestSessionManagement(t *testing.T) {
	c, err := curve.NewCurve(curve.Secp256k1)
	if err != nil {
		t.Fatalf("Failed to create curve: %v", err)
	}

	keyShare := &keygen.KeyShare{
		PartyID:   0,
		Threshold: 2,
		Parties:   3,
		Share:     big.NewInt(12345),
		PublicKey: &curve.Point{
			X: big.NewInt(1),
			Y: big.NewInt(2),
		},
		VerificationShares: make([]*curve.Point, 3),
		Curve:              c,
	}

	signer, err := NewThresholdSigner(keyShare)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Create test message
	msg := []byte("test message")
	msgHash := sha256.Sum256(msg)

	// Start session
	err = signer.StartSession(msgHash[:], 10*time.Minute)
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}

	if signer.sessionID == nil {
		t.Error("Session ID should not be nil")
	}

	if signer.sessionExpiry.IsZero() {
		t.Error("Session expiry should be set")
	}

	// Validate with wrong message should fail
	wrongMsg := []byte("wrong message")
	wrongHash := sha256.Sum256(wrongMsg)

	err = signer.validateSession(wrongHash[:])
	if err != ErrReplayAttack {
		t.Errorf("Expected ErrReplayAttack, got %v", err)
	}

	// Validate with correct message should succeed
	err = signer.validateSession(msgHash[:])
	if err != nil {
		t.Errorf("Session validation failed: %v", err)
	}
}

// TestSignatureVerification tests basic signature verification
func TestSignatureVerification(t *testing.T) {
	c, err := curve.NewCurve(curve.Secp256k1)
	if err != nil {
		t.Fatalf("Failed to create curve: %v", err)
	}

	// Create a valid signature for testing
	order := c.Order()

	// Use known values
	r := big.NewInt(12345)
	s := big.NewInt(67890)

	sig := &Signature{
		R: r,
		S: s,
	}

	// Create message hash
	msg := []byte("test message")
	msgHash := sha256.Sum256(msg)

	// Create a public key
	pk, err := c.ScalarBaseMult(big.NewInt(1))
	if err != nil {
		t.Fatalf("Failed to create public key: %v", err)
	}

	// Test with invalid signature (should fail)
	if Verify(pk, msgHash[:], sig, c) {
		t.Error("Invalid signature verified as valid")
	}

	// Test with nil inputs
	if Verify(nil, msgHash[:], sig, c) {
		t.Error("Nil public key should fail verification")
	}

	if Verify(pk, msgHash[:], nil, c) {
		t.Error("Nil signature should fail verification")
	}

	// Test with invalid R
	invalidSig := &Signature{
		R: big.NewInt(0),
		S: s,
	}

	if Verify(pk, msgHash[:], invalidSig, c) {
		t.Error("Signature with R=0 should fail verification")
	}

	// Test with out-of-range R
	outOfRangeSig := &Signature{
		R: new(big.Int).Add(order, big.NewInt(1)),
		S: s,
	}

	if Verify(pk, msgHash[:], outOfRangeSig, c) {
		t.Error("Signature with R > order should fail verification")
	}
}

// TestSignatureBytes tests signature serialization
func TestSignatureBytes(t *testing.T) {
	r := big.NewInt(12345)
	s := big.NewInt(67890)

	sig := &Signature{
		R: r,
		S: s,
	}

	// Serialize
	bytes := sig.Bytes()
	if len(bytes) != 64 {
		t.Errorf("Expected 64 bytes, got %d", len(bytes))
	}

	// Deserialize
	sig2, err := SignatureFromBytes(bytes)
	if err != nil {
		t.Fatalf("Failed to deserialize signature: %v", err)
	}

	if sig2.R.Cmp(r) != 0 {
		t.Errorf("R mismatch after deserialization")
	}

	if sig2.S.Cmp(s) != 0 {
		t.Errorf("S mismatch after deserialization")
	}

	// Test with invalid length
	_, err = SignatureFromBytes([]byte{1, 2, 3})
	if err != ErrInvalidSignature {
		t.Errorf("Expected ErrInvalidSignature, got %v", err)
	}
}

// TestTimeout tests timeout configuration
func TestTimeout(t *testing.T) {
	c, err := curve.NewCurve(curve.Secp256k1)
	if err != nil {
		t.Fatalf("Failed to create curve: %v", err)
	}

	keyShare := &keygen.KeyShare{
		PartyID:   0,
		Threshold: 2,
		Parties:   3,
		Share:     big.NewInt(12345),
		PublicKey: &curve.Point{
			X: big.NewInt(1),
			Y: big.NewInt(2),
		},
		VerificationShares: make([]*curve.Point, 3),
		Curve:              c,
	}

	signer, err := NewThresholdSigner(keyShare)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Default timeout
	if signer.roundTimeout != 5*time.Minute {
		t.Errorf("Expected default timeout 5m, got %v", signer.roundTimeout)
	}

	// Set custom timeout
	signer.SetTimeout(10 * time.Minute)
	if signer.roundTimeout != 10*time.Minute {
		t.Errorf("Expected timeout 10m, got %v", signer.roundTimeout)
	}
}

// TestCleanup tests sensitive data cleanup
func TestCleanup(t *testing.T) {
	c, err := curve.NewCurve(curve.Secp256k1)
	if err != nil {
		t.Fatalf("Failed to create curve: %v", err)
	}

	keyShare := &keygen.KeyShare{
		PartyID:   0,
		Threshold: 2,
		Parties:   3,
		Share:     big.NewInt(12345),
		PublicKey: &curve.Point{
			X: big.NewInt(1),
			Y: big.NewInt(2),
		},
		VerificationShares: make([]*curve.Point, 3),
		Curve:              c,
	}

	signer, err := NewThresholdSigner(keyShare)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Set up state
	signer.round1State = &round1State{
		k:     big.NewInt(999),
		gamma: big.NewInt(888),
	}

	signer.round3State = &round3State{
		partialSig: big.NewInt(777),
	}

	// Cleanup
	signer.cleanup()

	// Verify cleanup
	if signer.round1State != nil {
		t.Error("round1State should be nil after cleanup")
	}

	if signer.round3State != nil {
		t.Error("round3State should be nil after cleanup")
	}
}

// Benchmark tests
func BenchmarkSignatureVerification(b *testing.B) {
	c, _ := curve.NewCurve(curve.Secp256k1)

	r := big.NewInt(12345)
	s := big.NewInt(67890)

	sig := &Signature{
		R: r,
		S: s,
	}

	msg := []byte("test message")
	msgHash := sha256.Sum256(msg)
	pk, _ := c.ScalarBaseMult(big.NewInt(1))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(pk, msgHash[:], sig, c)
	}
}

func BenchmarkSignatureBytes(b *testing.B) {
	r := big.NewInt(12345)
	s := big.NewInt(67890)

	sig := &Signature{
		R: r,
		S: s,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sig.Bytes()
	}
}
