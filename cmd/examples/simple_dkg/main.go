// Package main demonstrates simple 2-of-3 Distributed Key Generation
package main

import (
	"fmt"
	"log"

	"github.com/Caqil/mpc-tss/pkg/crypto/curve"
	"github.com/Caqil/mpc-tss/pkg/keygen"
)

func main() {
	fmt.Println("=== Simple DKG Example: 2-of-3 Threshold ===")

	// Configuration
	threshold := 2
	totalParties := 3

	// Phase 1: Create DKG instances for each party
	fmt.Println("Phase 1: Creating DKG instances...")
	dkgs := make([]*keygen.DKGProtocol, totalParties)
	for i := 0; i < totalParties; i++ {
		dkg, err := keygen.NewDKGProtocol(i, threshold, totalParties, curve.Secp256k1)
		if err != nil {
			log.Fatalf("Failed to create DKG for party %d: %v", i, err)
		}
		dkgs[i] = dkg
		fmt.Printf("  ✓ Party %d initialized\n", i)
	}

	// Phase 2: Round 1 - Generate and broadcast commitments
	fmt.Println("\nPhase 2: Round 1 - Broadcasting commitments...")
	round1Data := make([]*keygen.Round1Data, totalParties)
	for i := 0; i < totalParties; i++ {
		data, err := dkgs[i].Round1()
		if err != nil {
			log.Fatalf("Party %d Round1 failed: %v", i, err)
		}
		round1Data[i] = data
		fmt.Printf("  ✓ Party %d: Generated %d commitments\n", i, len(data.Commitments))
	}

	fmt.Println("  ✓ All parties generated Round 1 data")

	// Phase 3: Round 2 - Exchange secret shares
	fmt.Println("\nPhase 3: Round 2 - Exchanging secret shares...")
	round2Data := make([][]*keygen.Round2Data, totalParties)
	for i := 0; i < totalParties; i++ {
		// Each party processes all Round 1 data
		shares, err := dkgs[i].Round2(round1Data)
		if err != nil {
			log.Fatalf("Party %d Round2 failed: %v", i, err)
		}
		round2Data[i] = shares
		fmt.Printf("  ✓ Party %d: Generated %d shares\n", i, len(shares))
	}

	// Collect all Round 2 shares for each party
	fmt.Println("  ✓ All parties generated Round 2 shares")

	// Phase 4: Round 3 - Finalize and compute key shares
	fmt.Println("\nPhase 4: Round 3 - Finalizing key shares...")

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
			log.Fatalf("Party %d Round3 failed: %v", i, err)
		}
		keyShares[i] = share
		fmt.Printf("  ✓ Party %d: Key share generated\n", i)
	}

	// Verify all parties have the same public key
	fmt.Println("\nPhase 5: Verification...")
	publicKey := keyShares[0].PublicKey
	for i := 1; i < totalParties; i++ {
		if keyShares[i].PublicKey.X.Cmp(publicKey.X) != 0 ||
			keyShares[i].PublicKey.Y.Cmp(publicKey.Y) != 0 {
			log.Fatalf("Party %d has different public key!", i)
		}
	}
	fmt.Println("  ✓ All parties have consistent public key")

	// Display results
	fmt.Println("\n=== DKG Complete! ===")
	fmt.Printf("Threshold: %d-of-%d\n", threshold, totalParties)
	fmt.Printf("Public Key X: %x...\n", publicKey.X.Bytes()[:8])
	fmt.Printf("Public Key Y: %x...\n", publicKey.Y.Bytes()[:8])
	fmt.Println("\nKey shares generated successfully!")
	fmt.Println("Any", threshold, "parties can now collaboratively sign messages.")
}
