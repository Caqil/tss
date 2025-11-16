// Package main demonstrates threshold signature generation
package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"time"

	"github.com/Caqil/mpc-tss/pkg/crypto/curve"
	"github.com/Caqil/mpc-tss/pkg/keygen"
	"github.com/Caqil/mpc-tss/pkg/signing"
)

func main() {
	fmt.Println("=== Simple Threshold Signing Example: 2-of-3 ===\n")

	threshold := 2
	totalParties := 3

	// Phase 1: Generate distributed keys using DKG
	fmt.Println("Phase 1: Distributed Key Generation (DKG)...")
	keyShares := runDKG(threshold, totalParties)
	fmt.Printf("  ✓ Generated %d key shares\n", len(keyShares))
	fmt.Printf("  ✓ Public Key: %x...%x\n",
		keyShares[0].PublicKey.X.Bytes()[:4],
		keyShares[0].PublicKey.X.Bytes()[len(keyShares[0].PublicKey.X.Bytes())-4:])

	// Phase 2: Create message to sign
	fmt.Println("\nPhase 2: Preparing message...")
	message := []byte("Transfer 100 BTC from Alice to Bob")
	messageHash := sha256.Sum256(message)
	fmt.Printf("  Message: %s\n", message)
	fmt.Printf("  Hash: %x\n", messageHash[:16])

	// Phase 3: Select signing parties (any threshold parties can sign)
	fmt.Println("\nPhase 3: Selecting signing parties...")
	signingParties := []int{0, 1} // Use parties 0 and 1 (could be any 2)
	fmt.Printf("  ✓ Selected parties: %v\n", signingParties)

	// Phase 4: Run threshold signing protocol
	fmt.Println("\nPhase 4: Threshold Signing Protocol...")
	signature := runThresholdSigning(keyShares, signingParties, messageHash[:])
	fmt.Printf("  ✓ Signature generated\n")
	fmt.Printf("    R: %x\n", signature.R.Bytes()[:16])
	fmt.Printf("    S: %x\n", signature.S.Bytes()[:16])

	// Phase 5: Verify signature
	fmt.Println("\nPhase 5: Signature Verification...")
	valid := signing.Verify(keyShares[0].PublicKey, messageHash[:], signature, keyShares[0].Curve)
	if !valid {
		log.Fatal("❌ Signature verification failed!")
	}
	fmt.Println("  ✓ Signature verified successfully!")

	// Phase 6: Test with different signing parties
	fmt.Println("\nPhase 6: Testing with different signing parties...")
	signingParties2 := []int{1, 2} // Use parties 1 and 2
	fmt.Printf("  Selected parties: %v\n", signingParties2)

	message2 := []byte("Transfer 50 BTC from Bob to Charlie")
	messageHash2 := sha256.Sum256(message2)
	signature2 := runThresholdSigning(keyShares, signingParties2, messageHash2[:])

	valid2 := signing.Verify(keyShares[0].PublicKey, messageHash2[:], signature2, keyShares[0].Curve)
	if !valid2 {
		log.Fatal("❌ Second signature verification failed!")
	}
	fmt.Println("  ✓ Second signature verified successfully!")

	// Summary
	fmt.Println("\n=== Threshold Signing Complete! ===")
	fmt.Printf("Threshold: %d-of-%d\n", threshold, totalParties)
	fmt.Println("\nKey Features Demonstrated:")
	fmt.Println("  ✓ Distributed Key Generation (DKG)")
	fmt.Println("  ✓ Threshold signature generation")
	fmt.Println("  ✓ Any threshold parties can sign")
	fmt.Println("  ✓ Signature verification")
	fmt.Println("  ✓ Multiple signatures with same key")
}

// runDKG performs a complete DKG protocol and returns key shares
func runDKG(threshold, totalParties int) []*keygen.KeyShare {
	// Create DKG instances for all parties
	dkgs := make([]*keygen.DKGProtocol, totalParties)
	for i := 0; i < totalParties; i++ {
		dkg, err := keygen.NewDKGProtocol(i, threshold, totalParties, curve.Secp256k1)
		if err != nil {
			log.Fatalf("Failed to create DKG for party %d: %v", i, err)
		}
		dkgs[i] = dkg
	}

	// Round 1: Generate commitments
	round1Data := make([]*keygen.Round1Data, totalParties)
	for i := 0; i < totalParties; i++ {
		data, err := dkgs[i].Round1()
		if err != nil {
			log.Fatalf("Party %d Round1 failed: %v", i, err)
		}
		round1Data[i] = data
	}

	// Round 2: Generate shares
	round2Data := make([][]*keygen.Round2Data, totalParties)
	for i := 0; i < totalParties; i++ {
		shares, err := dkgs[i].Round2(round1Data)
		if err != nil {
			log.Fatalf("Party %d Round2 failed: %v", i, err)
		}
		round2Data[i] = shares
	}

	// Organize Round 2 data for each party
	allRound2Shares := make([][]*keygen.Round2Data, totalParties)
	for i := 0; i < totalParties; i++ {
		allRound2Shares[i] = make([]*keygen.Round2Data, 0, totalParties-1)
		for j := 0; j < totalParties; j++ {
			for _, share := range round2Data[j] {
				if share.ToParty == i {
					allRound2Shares[i] = append(allRound2Shares[i], share)
				}
			}
		}
	}

	// Round 3: Finalize key shares
	keyShares := make([]*keygen.KeyShare, totalParties)
	for i := 0; i < totalParties; i++ {
		share, err := dkgs[i].Round3(allRound2Shares[i])
		if err != nil {
			log.Fatalf("Party %d Round3 failed: %v", i, err)
		}
		keyShares[i] = share
	}

	return keyShares
}

// runThresholdSigning performs threshold signing with selected parties
func runThresholdSigning(allKeyShares []*keygen.KeyShare, signingParties []int, messageHash []byte) *signing.Signature {
	numSigners := len(signingParties)

	// Generate a shared session ID for all parties
	sessionID := sha256.Sum256(append(messageHash, []byte("session")...))

	// Create signers for selected parties
	signers := make([]*signing.ThresholdSigner, numSigners)
	for i, partyID := range signingParties {
		signer, err := signing.NewThresholdSigner(allKeyShares[partyID])
		if err != nil {
			log.Fatalf("Failed to create signer for party %d: %v", partyID, err)
		}

		// Start signing session with shared session ID
		if err := signer.StartSessionWithID(messageHash, sessionID[:], 5*time.Minute); err != nil {
			log.Fatalf("Failed to start session for party %d: %v", partyID, err)
		}

		signers[i] = signer
	}

	// Round 1: Generate commitments
	round1Data := make([]*signing.SignRound1Data, numSigners)
	for i := 0; i < numSigners; i++ {
		data, err := signers[i].SignRound1(messageHash)
		if err != nil {
			log.Fatalf("Party %d SignRound1 failed: %v", signingParties[i], err)
		}
		round1Data[i] = data
	}

	// Round 2: Reveal nonces
	round2Data := make([]*signing.SignRound2Data, numSigners)
	for i := 0; i < numSigners; i++ {
		// Filter out own data for each party
		othersRound1 := make([]*signing.SignRound1Data, 0, numSigners-1)
		for j := 0; j < numSigners; j++ {
			if i != j {
				othersRound1 = append(othersRound1, round1Data[j])
			}
		}

		data, err := signers[i].SignRound2(messageHash, othersRound1)
		if err != nil {
			log.Fatalf("Party %d SignRound2 failed: %v", signingParties[i], err)
		}
		round2Data[i] = data
	}

	// Round 3: Generate partial signatures
	round3Data := make([]*signing.SignRound3Data, numSigners)
	for i := 0; i < numSigners; i++ {
		// Filter out own data for each party
		othersRound2 := make([]*signing.SignRound2Data, 0, numSigners-1)
		for j := 0; j < numSigners; j++ {
			if i != j {
				othersRound2 = append(othersRound2, round2Data[j])
			}
		}

		data, err := signers[i].SignRound3(messageHash, othersRound2)
		if err != nil {
			log.Fatalf("Party %d SignRound3 failed: %v", signingParties[i], err)
		}
		round3Data[i] = data
	}

	// Round 4: Aggregate signatures
	// Filter out own data for party 0 (any party can aggregate)
	othersRound3 := make([]*signing.SignRound3Data, 0, numSigners-1)
	for j := 1; j < numSigners; j++ {
		othersRound3 = append(othersRound3, round3Data[j])
	}

	signature, err := signers[0].SignRound4(messageHash, othersRound3)
	if err != nil {
		log.Fatalf("SignRound4 failed: %v", err)
	}

	return signature
}
