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
	fmt.Println("=== Debug Threshold Signing ===\n")

	threshold := 2
	totalParties := 3

	// DKG
	dkgs := make([]*keygen.DKGProtocol, totalParties)
	for i := 0; i < totalParties; i++ {
		dkg, _ := keygen.NewDKGProtocol(i, threshold, totalParties, curve.Secp256k1)
		dkgs[i] = dkg
	}

	round1Data := make([]*keygen.Round1Data, totalParties)
	for i := 0; i < totalParties; i++ {
		round1Data[i], _ = dkgs[i].Round1()
	}

	round2Data := make([][]*keygen.Round2Data, totalParties)
	for i := 0; i < totalParties; i++ {
		round2Data[i], _ = dkgs[i].Round2(round1Data)
	}

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

	keyShares := make([]*keygen.KeyShare, totalParties)
	for i := 0; i < totalParties; i++ {
		keyShares[i], _ = dkgs[i].Round3(allRound2Shares[i])
	}

	fmt.Println("✓ DKG Complete")
	fmt.Printf("Public Key: %x\n\n", keyShares[0].PublicKey.X.Bytes()[:8])

	// Signing
	message := []byte("Test message")
	messageHash := sha256.Sum256(message)
	
	signingParties := []int{0, 1}
	sessionID := sha256.Sum256(append(messageHash[:], []byte("session")...))

	signers := make([]*signing.ThresholdSigner, 2)
	for i, partyID := range signingParties {
		signers[i], _ = signing.NewThresholdSigner(keyShares[partyID])
		signers[i].StartSessionWithID(messageHash[:], sessionID[:], 5*time.Minute)
	}

	// Round 1
	round1 := make([]*signing.SignRound1Data, 2)
	for i := 0; i < 2; i++ {
		round1[i], _ = signers[i].SignRound1(messageHash[:])
	}

	// Round 2
	round2 := make([]*signing.SignRound2Data, 2)
	for i := 0; i < 2; i++ {
		others := []*signing.SignRound1Data{round1[1-i]}
		round2[i], _ = signers[i].SignRound2(messageHash[:], others)
	}

	// Round 3
	round3 := make([]*signing.SignRound3Data, 2)
	for i := 0; i < 2; i++ {
		others := []*signing.SignRound2Data{round2[1-i]}
		round3[i], _ = signers[i].SignRound3(messageHash[:], others)
	}

	// Round 4
	sig, err := signers[0].SignRound4(messageHash[:], []*signing.SignRound3Data{round3[1]})
	if err != nil {
		log.Fatalf("SignRound4 failed: %v", err)
	}

	fmt.Println("✓ Signature generated")
	fmt.Printf("R: %x\n", sig.R.Bytes()[:8])
	fmt.Printf("S: %x\n", sig.S.Bytes()[:8])
	fmt.Printf("RPoint: %x\n", sig.RPoint.X.Bytes()[:8])
}
