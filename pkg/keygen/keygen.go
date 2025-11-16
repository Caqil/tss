// Package keygen implements distributed key generation protocols
package keygen

import (
	"math/big"

	"github.com/Caqil/mpc-tss/internal/math"
	"github.com/Caqil/mpc-tss/internal/security"
	"github.com/Caqil/mpc-tss/pkg/crypto/curve"
)

// KeyShare represents a party's share of the distributed key
type KeyShare struct {
	// PartyID is this party's identifier
	PartyID int

	// Threshold is the minimum number of parties needed to sign
	Threshold int

	// Parties is the total number of parties
	Parties int

	// Share is this party's secret share
	Share *big.Int

	// PublicKey is the group's public key
	PublicKey *curve.Point

	// VerificationShares are public verification points for all parties
	VerificationShares []*curve.Point

	// Curve is the elliptic curve being used
	Curve curve.Curve
}

// DKGProtocol manages the distributed key generation protocol
type DKGProtocol struct {
	partyID   int
	threshold int
	parties   int
	curve     curve.Curve

	// Private state
	vss            *FeldmanVSS
	polynomial     *math.Polynomial
	myShares       map[int]*math.Share // Shares I send to others
	receivedData   map[int]*Round1Data // Round 1 data from others
	receivedShares map[int]*math.Share // Round 2 shares from others
}

// NewDKGProtocol creates a new DKG protocol instance
func NewDKGProtocol(partyID, threshold, parties int, curveType curve.CurveType) (*DKGProtocol, error) {
	// Validate parameters
	if err := security.ValidateThreshold(threshold, parties); err != nil {
		return nil, err
	}

	if err := security.ValidatePartyID(partyID, parties); err != nil {
		return nil, err
	}

	// Create curve
	c, err := curve.NewCurve(curveType)
	if err != nil {
		return nil, err
	}

	// Create Feldman VSS instance
	vss, err := NewFeldmanVSS(threshold, parties, c)
	if err != nil {
		return nil, err
	}

	return &DKGProtocol{
		partyID:        partyID,
		threshold:      threshold,
		parties:        parties,
		curve:          c,
		vss:            vss,
		myShares:       make(map[int]*math.Share),
		receivedData:   make(map[int]*Round1Data),
		receivedShares: make(map[int]*math.Share),
	}, nil
}

// Round1Data contains data broadcast in DKG round 1
type Round1Data struct {
	PartyID     int
	Commitments []*curve.Point
}

// Round2Data contains data sent in DKG round 2
type Round2Data struct {
	FromParty int
	ToParty   int
	Share     *big.Int
}

// Round1 generates and broadcasts polynomial commitments
// Each party generates a random polynomial and commits to its coefficients
func (d *DKGProtocol) Round1() (*Round1Data, error) {
	// Generate random secret (will be the constant term a_0)
	order := d.curve.Order()
	secret, err := security.GenerateRandomScalar(order)
	if err != nil {
		return nil, err
	}

	// Create shares using Feldman VSS
	shares, commitments, err := d.vss.Share(secret)
	if err != nil {
		security.SecureZero(secret.Bytes())
		return nil, err
	}

	// Store shares for Round 2 distribution
	for i, share := range shares {
		d.myShares[i] = share
	}

	// Securely zero the secret (we only need the polynomial)
	security.SecureZero(secret.Bytes())

	return &Round1Data{
		PartyID:     d.partyID,
		Commitments: commitments,
	}, nil
}

// Round2 generates shares for other parties
// After receiving all Round1 commitments, send shares to each party
// Automatically filters out this party's own Round1 data
func (d *DKGProtocol) Round2(round1Data []*Round1Data) ([]*Round2Data, error) {
	// Filter out own Round1 data and validate
	receivedCount := 0
	for _, data := range round1Data {
		if data.PartyID == d.partyID {
			continue // Skip own data
		}
		d.receivedData[data.PartyID] = data
		receivedCount++
	}

	// Verify we received data from all other parties
	if receivedCount != d.parties-1 {
		return nil, ErrMissingRound1Data
	}

	// Create Round2 data: one share for each other party
	round2Data := make([]*Round2Data, 0, d.parties-1)

	for partyID := 0; partyID < d.parties; partyID++ {
		if partyID == d.partyID {
			continue // Don't send to self
		}

		// Get the share for this party
		share, ok := d.myShares[partyID]
		if !ok {
			return nil, ErrMissingShare
		}

		round2Data = append(round2Data, &Round2Data{
			FromParty: d.partyID,
			ToParty:   partyID,
			Share:     share.Value,
		})
	}

	return round2Data, nil
}

// Round3 verifies received shares and computes final key
// Verifies all shares using Feldman VSS commitments, then combines
func (d *DKGProtocol) Round3(round2Data []*Round2Data) (*KeyShare, error) {
	if len(round2Data) != d.parties-1 {
		return nil, ErrMissingRound2Data
	}

	// Verify and store received shares
	for _, data := range round2Data {
		if data.ToParty != d.partyID {
			return nil, ErrInvalidShare
		}

		// Get commitments from Round1
		round1, ok := d.receivedData[data.FromParty]
		if !ok {
			return nil, ErrMissingCommitments
		}

		// Create share object for verification
		share := &math.Share{
			Index: big.NewInt(int64(d.partyID + 1)), // 1-indexed
			Value: data.Share,
		}

		// Verify share using Feldman VSS
		if !d.vss.VerifyShare(share, round1.Commitments) {
			return nil, ErrShareVerificationFailed
		}

		d.receivedShares[data.FromParty] = share
	}

	// Compute final key share as sum of all received shares + own share
	order := d.curve.Order()
	finalShare := big.NewInt(0)

	// Add own share
	myShare := d.myShares[d.partyID]
	finalShare.Add(finalShare, myShare.Value)
	finalShare.Mod(finalShare, order)

	// Add received shares
	for _, share := range d.receivedShares {
		finalShare.Add(finalShare, share.Value)
		finalShare.Mod(finalShare, order)
	}

	// Compute group public key as sum of all first commitments
	// PK = C_{0,0} + C_{1,0} + ... + C_{n-1,0}
	publicKey := d.vss.Commitments[0].Clone()

	for _, round1 := range d.receivedData {
		var err error
		publicKey, err = d.curve.Add(publicKey, round1.Commitments[0])
		if err != nil {
			return nil, err
		}
	}

	// Compute verification shares for each party
	// These are the public keys corresponding to each party's final share
	verificationShares := make([]*curve.Point, d.parties)

	for partyID := 0; partyID < d.parties; partyID++ {
		index := big.NewInt(int64(partyID + 1)) // 1-indexed

		// Sum all parties' commitments evaluated at this index
		// VS_i = ∑_j f_j(i)*G where f_j is party j's polynomial
		vs, err := d.computeVerificationShare(index)
		if err != nil {
			return nil, err
		}

		verificationShares[partyID] = vs
	}

	return &KeyShare{
		PartyID:            d.partyID,
		Threshold:          d.threshold,
		Parties:            d.parties,
		Share:              finalShare,
		PublicKey:          publicKey,
		VerificationShares: verificationShares,
		Curve:              d.curve,
	}, nil
}

// computeVerificationShare computes the verification share for a given index
func (d *DKGProtocol) computeVerificationShare(index *big.Int) (*curve.Point, error) {
	order := d.curve.Order()

	// Start with own contribution
	result, err := evaluateCommitment(d.vss.Commitments, index, d.curve, order)
	if err != nil {
		return nil, err
	}

	// Add all other parties' contributions
	for _, round1 := range d.receivedData {
		contrib, err := evaluateCommitment(round1.Commitments, index, d.curve, order)
		if err != nil {
			return nil, err
		}

		result, err = d.curve.Add(result, contrib)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// evaluateCommitment evaluates committed polynomial at a point
// Returns: C_0 * C_1^x * C_2^{x^2} * ...
func evaluateCommitment(commitments []*curve.Point, x *big.Int, c curve.Curve, order *big.Int) (*curve.Point, error) {
	if len(commitments) == 0 {
		return nil, ErrInvalidCommitment
	}

	// Start with C_0
	result := commitments[0].Clone()

	// x^j for each term
	xPower := new(big.Int).Set(x)

	for j := 1; j < len(commitments); j++ {
		// Compute C_j^{x^j}
		term, err := c.ScalarMult(commitments[j], xPower)
		if err != nil {
			return nil, err
		}

		// Add to result
		result, err = c.Add(result, term)
		if err != nil {
			return nil, err
		}

		// Update power for next iteration
		xPower = new(big.Int).Mul(xPower, x)
		xPower.Mod(xPower, order)
	}

	return result, nil
}
