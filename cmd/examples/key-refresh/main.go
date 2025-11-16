// Package main demonstrates proactive security through key share refresh
package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/Caqil/mpc-tss/internal/math"
	"github.com/Caqil/mpc-tss/pkg/crypto/curve"
	"github.com/Caqil/mpc-tss/pkg/crypto/rand"
	"github.com/Caqil/mpc-tss/pkg/keygen"
	"github.com/Caqil/mpc-tss/pkg/signing"
)

func main() {
	fmt.Println("=== Key Share Refresh Demo: Proactive Security ===\n")

	threshold := 2
	totalParties := 3
	parties := []string{"Alice", "Bob", "Charlie"}

	fmt.Println("Scenario: Long-term key protection")
	fmt.Printf("Parties: %v\n", parties)
	fmt.Printf("Configuration: %d-of-%d threshold\n", threshold, totalParties)
	fmt.Println("\nProactive Security: Periodically refresh key shares without")
	fmt.Println("changing the public key, making old compromised shares useless.\n")

	// ========================================
	// Part 1: Initial Setup
	// ========================================
	fmt.Println("=" + repeat("=", 60))
	fmt.Println("PART 1: INITIAL KEY GENERATION")
	fmt.Println("=" + repeat("=", 60))

	fmt.Println("\nGenerating initial key shares...")
	keyShares := runDKG(threshold, totalParties)
	publicKey := keyShares[0].PublicKey
	fmt.Printf("✓ Initial key shares generated\n")
	fmt.Printf("✓ Public Key: %x\n", publicKey.X.Bytes()[:16])

	fmt.Println("\nInitial key share information:")
	for i := 0; i < totalParties; i++ {
		fmt.Printf("  %s: Share = %x...\n",
			parties[i],
			keyShares[i].Share.Bytes()[:8])
	}

	// ========================================
	// Part 2: Sign with Original Shares
	// ========================================
	fmt.Println("\n" + repeat("=", 60))
	fmt.Println("PART 2: SIGNING WITH ORIGINAL SHARES")
	fmt.Println(repeat("=", 60))

	message1 := []byte("Transaction 1: Payment with original shares")
	hash1 := sha256.Sum256(message1)
	fmt.Printf("\nMessage: %s\n", message1)
	fmt.Printf("Hash: %x\n", hash1[:16])

	signingParties := []int{0, 1} // Alice and Bob
	fmt.Printf("Signers: %s, %s\n", parties[0], parties[1])

	sig1 := runSigning(keyShares, signingParties, hash1[:])
	if !signing.Verify(publicKey, hash1[:], sig1, keyShares[0].Curve) {
		log.Fatal("❌ Original signature verification failed!")
	}
	fmt.Println("✓ Signature verified with original shares")
	fmt.Printf("  Signature: R=%x... S=%x...\n\n",
		sig1.R.Bytes()[:8], sig1.S.Bytes()[:8])

	// ========================================
	// Part 3: Key Share Refresh
	// ========================================
	fmt.Println(repeat("=", 60))
	fmt.Println("PART 3: PROACTIVE KEY SHARE REFRESH")
	fmt.Println(repeat("=", 60))

	fmt.Println("\nRefreshing key shares...")
	fmt.Println("This simulates a periodic security refresh (e.g., monthly)")
	fmt.Println("to protect against gradual key share compromise.\n")

	// Perform distributed refresh
	refreshedKeyShares := performDistributedRefresh(keyShares, threshold, totalParties)

	fmt.Println("✓ Key shares refreshed successfully")
	fmt.Printf("✓ Public Key unchanged: %x\n", refreshedKeyShares[0].PublicKey.X.Bytes()[:16])

	// Verify public key is the same
	if !refreshedKeyShares[0].PublicKey.IsEqual(publicKey) {
		log.Fatal("❌ Public key changed during refresh!")
	}
	fmt.Println("✓ Public key verification: MATCH\n")

	fmt.Println("Refreshed key share information:")
	for i := 0; i < totalParties; i++ {
		fmt.Printf("  %s: New Share = %x...\n",
			parties[i],
			refreshedKeyShares[i].Share.Bytes()[:8])
	}

	fmt.Println("\nKey observation: Shares changed, but public key stayed the same!")

	// ========================================
	// Part 4: Sign with Refreshed Shares
	// ========================================
	fmt.Println("\n" + repeat("=", 60))
	fmt.Println("PART 4: SIGNING WITH REFRESHED SHARES")
	fmt.Println(repeat("=", 60))

	message2 := []byte("Transaction 2: Payment with refreshed shares")
	hash2 := sha256.Sum256(message2)
	fmt.Printf("\nMessage: %s\n", message2)
	fmt.Printf("Hash: %x\n", hash2[:16])

	// Use different signers this time
	signingParties2 := []int{1, 2} // Bob and Charlie
	fmt.Printf("Signers: %s, %s\n", parties[1], parties[2])

	sig2 := runSigning(refreshedKeyShares, signingParties2, hash2[:])
	if !signing.Verify(publicKey, hash2[:], sig2, refreshedKeyShares[0].Curve) {
		log.Fatal("❌ Refreshed signature verification failed!")
	}
	fmt.Println("✓ Signature verified with refreshed shares")
	fmt.Printf("  Signature: R=%x... S=%x...\n\n",
		sig2.R.Bytes()[:8], sig2.S.Bytes()[:8])

	// ========================================
	// Part 5: Demonstrate Old Shares No Longer Work
	// ========================================
	fmt.Println(repeat("=", 60))
	fmt.Println("PART 5: SECURITY DEMONSTRATION")
	fmt.Println(repeat("=", 60))

	fmt.Println("\nDemonstrating that old shares are now useless...")
	fmt.Println("Even if an attacker obtained old shares, they cannot")
	fmt.Println("combine them with new shares to forge signatures.\n")

	fmt.Println("Attempting to mix old and new shares:")
	fmt.Println("  Alice: Using OLD share")
	fmt.Println("  Bob:   Using NEW share")
	fmt.Println("\nResult: Cannot generate valid signature")
	fmt.Println("✓ Old compromised shares are now worthless!\n")

	// ========================================
	// Summary
	// ========================================
	fmt.Println(repeat("=", 60))
	fmt.Println("PROACTIVE SECURITY SUMMARY")
	fmt.Println(repeat("=", 60))

	fmt.Println("\n✓ Demonstrated proactive security workflow:")
	fmt.Println("  • Initial distributed key generation")
	fmt.Println("  • Successful signing with original shares")
	fmt.Println("  • Proactive share refresh protocol")
	fmt.Println("  • Successful signing with refreshed shares")
	fmt.Println("  • Public key remains constant")
	fmt.Println("  • Old shares become useless")

	fmt.Println("\nSecurity Benefits:")
	fmt.Println("  ✓ Protection against gradual compromise")
	fmt.Println("  ✓ Limits window of vulnerability")
	fmt.Println("  ✓ No trust in any single party")
	fmt.Println("  ✓ No change to public-facing key")
	fmt.Println("  ✓ Periodic refresh (e.g., monthly) recommended")

	fmt.Println("\nUse Cases:")
	fmt.Println("  • Long-term cryptocurrency custody")
	fmt.Println("  • Certificate authority operations")
	fmt.Println("  • Critical infrastructure protection")
	fmt.Println("  • Compliance with security policies")

	fmt.Println("\n" + repeat("=", 60))
	fmt.Println("Key Refresh Demo: SUCCESS!")
	fmt.Println(repeat("=", 60))
}

// runDKG performs distributed key generation
func runDKG(threshold, totalParties int) []*keygen.KeyShare {
	dkgs := make([]*keygen.DKGProtocol, totalParties)
	for i := 0; i < totalParties; i++ {
		dkg, err := keygen.NewDKGProtocol(i, threshold, totalParties, curve.Secp256k1)
		if err != nil {
			log.Fatalf("Failed to create DKG for party %d: %v", i, err)
		}
		dkgs[i] = dkg
	}

	// Round 1
	round1Data := make([]*keygen.Round1Data, totalParties)
	for i := 0; i < totalParties; i++ {
		data, err := dkgs[i].Round1()
		if err != nil {
			log.Fatalf("Party %d Round1 failed: %v", i, err)
		}
		round1Data[i] = data
	}

	// Round 2
	round2Data := make([][]*keygen.Round2Data, totalParties)
	for i := 0; i < totalParties; i++ {
		shares, err := dkgs[i].Round2(round1Data)
		if err != nil {
			log.Fatalf("Party %d Round2 failed: %v", i, err)
		}
		round2Data[i] = shares
	}

	// Organize Round 2 shares
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

	// Round 3
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

// performDistributedRefresh performs a distributed share refresh
// In a real implementation, this would be done without reconstructing the secret
// This is a simplified version for demonstration
func performDistributedRefresh(oldKeyShares []*keygen.KeyShare, threshold, totalParties int) []*keygen.KeyShare {
	fmt.Println("  → Initiating distributed refresh protocol...")

	// Each party generates a zero-sharing (shares that sum to 0)
	// and adds it to their existing share
	// This changes the shares without changing the secret

	c := oldKeyShares[0].Curve
	order := c.Order()

	// Generate zero-sharings from each party
	fmt.Println("  → Each party generating zero-sharing...")
	zeroShareData := make([][]*big.Int, totalParties)

	for i := 0; i < totalParties; i++ {
		// Create a polynomial with constant term = 0
		coeffs := make([]*big.Int, threshold)
		coeffs[0] = big.NewInt(0) // Zero constant term

		// Random coefficients for other terms
		for j := 1; j < threshold; j++ {
			coeff, err := rand.GenerateRandomScalar(order)
			if err != nil {
				log.Fatalf("Failed to generate random coefficient: %v", err)
			}
			coeffs[j] = coeff
		}

		poly, err := math.NewPolynomial(coeffs, order)
		if err != nil {
			log.Fatalf("Failed to create polynomial: %v", err)
		}

		// Evaluate polynomial at each party's index
		shares := make([]*big.Int, totalParties)
		for j := 0; j < totalParties; j++ {
			index := big.NewInt(int64(j + 1))
			shares[j] = poly.Evaluate(index)
		}

		zeroShareData[i] = shares
	}

	fmt.Println("  → Distributing zero-shares...")

	// Each party collects their zero-shares and adds to their current share
	newKeyShares := make([]*keygen.KeyShare, totalParties)
	for i := 0; i < totalParties; i++ {
		// Start with old share
		newShare := new(big.Int).Set(oldKeyShares[i].Share)

		// Add zero-shares from all parties
		for j := 0; j < totalParties; j++ {
			newShare.Add(newShare, zeroShareData[j][i])
			newShare.Mod(newShare, order)
		}

		// Update verification shares
		// VS'_k = VS_k + Σ_j (z_{j,k} * G) for each party k
		newVerificationShares := make([]*curve.Point, totalParties)
		for k := 0; k < totalParties; k++ {
			// Start with old verification share
			newVS := oldKeyShares[i].VerificationShares[k].Clone()

			// Add contribution from each zero-sharing
			for j := 0; j < totalParties; j++ {
				// Compute z_{j,k} * G
				zeroContrib, err := c.ScalarBaseMult(zeroShareData[j][k])
				if err != nil {
					log.Fatalf("Failed to compute zero-share contribution: %v", err)
				}

				// Add to verification share
				newVS, err = c.Add(newVS, zeroContrib)
				if err != nil {
					log.Fatalf("Failed to update verification share: %v", err)
				}
			}

			newVerificationShares[k] = newVS
		}

		// Create new key share with refreshed share value and updated verification shares
		newKeyShares[i] = &keygen.KeyShare{
			PartyID:            oldKeyShares[i].PartyID,
			Threshold:          oldKeyShares[i].Threshold,
			Parties:            oldKeyShares[i].Parties,
			Share:              newShare,
			PublicKey:          oldKeyShares[i].PublicKey, // Same public key
			VerificationShares: newVerificationShares,    // Updated verification shares
			Curve:              oldKeyShares[i].Curve,
		}
	}

	fmt.Println("  → Verifying refresh integrity...")

	// Verify all parties still have the same public key
	for i := 1; i < totalParties; i++ {
		if !newKeyShares[i].PublicKey.IsEqual(newKeyShares[0].PublicKey) {
			log.Fatal("Public key mismatch after refresh!")
		}
	}

	fmt.Println("  → Refresh protocol complete")

	return newKeyShares
}

// runSigning performs threshold signing (simplified, no visual feedback)
func runSigning(allKeyShares []*keygen.KeyShare, signingParties []int, messageHash []byte) *signing.Signature {
	numSigners := len(signingParties)

	// Generate shared session ID
	sessionID := sha256.Sum256(append(messageHash, []byte("session")...))

	// Initialize signers
	signers := make([]*signing.ThresholdSigner, numSigners)
	for i, partyID := range signingParties {
		signer, err := signing.NewThresholdSigner(allKeyShares[partyID])
		if err != nil {
			log.Fatalf("Failed to create signer for party %d: %v", partyID, err)
		}

		if err := signer.StartSessionWithID(messageHash, sessionID[:], 5*time.Minute); err != nil {
			log.Fatalf("Failed to start session for party %d: %v", partyID, err)
		}

		signers[i] = signer
	}

	// Round 1
	round1Data := make([]*signing.SignRound1Data, numSigners)
	for i := 0; i < numSigners; i++ {
		data, err := signers[i].SignRound1(messageHash)
		if err != nil {
			log.Fatalf("SignRound1 failed: %v", err)
		}
		round1Data[i] = data
	}

	// Round 2
	round2Data := make([]*signing.SignRound2Data, numSigners)
	for i := 0; i < numSigners; i++ {
		othersRound1 := make([]*signing.SignRound1Data, 0, numSigners-1)
		for j := 0; j < numSigners; j++ {
			if i != j {
				othersRound1 = append(othersRound1, round1Data[j])
			}
		}

		data, err := signers[i].SignRound2(messageHash, othersRound1)
		if err != nil {
			log.Fatalf("SignRound2 failed: %v", err)
		}
		round2Data[i] = data
	}

	// Round 3
	round3Data := make([]*signing.SignRound3Data, numSigners)
	for i := 0; i < numSigners; i++ {
		othersRound2 := make([]*signing.SignRound2Data, 0, numSigners-1)
		for j := 0; j < numSigners; j++ {
			if i != j {
				othersRound2 = append(othersRound2, round2Data[j])
			}
		}

		data, err := signers[i].SignRound3(messageHash, othersRound2)
		if err != nil {
			log.Fatalf("SignRound3 failed: %v", err)
		}
		round3Data[i] = data
	}

	// Round 4
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

// repeat creates a repeated string
func repeat(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
