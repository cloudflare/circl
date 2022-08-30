package hstmaj

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/secretsharing"
)

const testThreshold = 2
const benchThreshold = 1
const benchn = 3
const benchnPrime = 3

// Generate ECDSA key
func genKey(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)

	if err != nil {
		panic(err)
	}

	if privateKey == nil {
		panic(err)
	}

	publicKey := &privateKey.PublicKey

	if publicKey == nil {
		panic(err)
	}
	return privateKey, publicKey

}

func core(t, n uint, prv *ecdsa.PrivateKey, myGroup group.Group, parties []partySign, curve elliptic.Curve) []secretsharing.Share {

	// Convert the ECDSA secret key bigint into a Scalar
	secretByte := prv.D.Bytes()
	secretScalar := myGroup.NewScalar()
	errBinary := secretScalar.UnmarshalBinary(secretByte)
	if errBinary != nil {
		panic(errBinary)
	}

	// Core distribute shares of secret key
	sharesk := genSecretShare(t, n, myGroup, secretScalar)
	return sharesk
}

// Jointly and sequentially compute shares for the nonce k , k^{-1} as well as x coordinate of [k]G
// Input: t, the threshold parameter
// Input: n, the number of parties
// Input: myGroup, the group we operate in
// Input: parties, the parties of size n
func preSign(t, n uint, myGroup group.Group, parties []partyPreSign) error {
	// Local: Parties initiate the parameters
	for i := uint(0); i < n; i++ {
		parties[i].LocalInit(i+1, n, myGroup)
	}

	// Local: Parties generate their local information for nonce k and blinding b
	for i := uint(0); i < n; i++ {
		parties[i].LocalGenkb(t, n)
	}

	// Round 1
	// Parties broadcast their local information for nonce k and blinding b
	// From party i to party j
	for i := uint(0); i < n; i++ {
		for j := uint(0); j < n; j++ {
			if i != j {
				errorLable := parties[j].LocalUpdatekb(t, n, parties[i].sski[j], parties[i].ssbi[j], parties[i].obfCoefki, parties[i].obfCoefbi, i)
				if errorLable != 0 {
					return errors.New("feldman verification failed")
				}
			}
			parties[j].obfCoefks[i] = parties[i].obfCoefki
			parties[j].obfCoefbs[i] = parties[i].obfCoefbi
		}
	}

	// Party j broadcast feldman coefficient received from party i to all other parties and everyone confirm they receive the same
	for j := uint(0); j < n; j++ {
		for i := uint(0); i < n; i++ {
			// party j sends feldman coefficient received from party i to party l!=i or j
			if i != j {
				for l := uint(0); l < n; l++ {
					if (l != i) && (l != j) {
						check := checkObf(t, parties[j].obfCoefbs[i], parties[l].obfCoefbs[i])
						if !check {
							return errors.New("broadcasting feldman coefficient failed")
						}
						check = checkObf(t, parties[j].obfCoefks[i], parties[l].obfCoefks[i])
						if !check {
							return errors.New("broadcasting feldman coefficient failed")
						}
					}
				}
			}

		}
	}

	// Local: Parties compute shares for k*b and [sharek]G
	sskb := make([]secretsharing.Share, n)
	for i := uint(0); i < n; i++ {
		parties[i].LocalSharekb()
		parties[i].LocalkG()
		sskb[i].ID = parties[i].sharekb.ID
		sskb[i].Share = parties[i].sharekb.Share.Copy()
	}

	// Round 2
	// A combiner, assume party 0, combines shares for kb and compute (kb)^{-1}
	if n < (2*t + 1) {
		return errors.New("at least 2t+1 parties are required for computing multiplication")
	}

	kbInv, err := parties[0].CombinerCompkbInv(t, n, sskb)
	if err != nil {
		return err
	}

	// A combiner, assume party 0, combines shares for [sharek]G, compute [k]G
	sskG := make([]group.Element, n)
	indexes := make([]group.Scalar, n)
	for i := uint(0); i < n; i++ {
		sskG[i] = parties[i].sharekG
		indexes[i] = myGroup.NewScalar()
		indexes[i].SetUint64(uint64(parties[i].index))
	}

	xCoor, err := parties[0].CombinerCompkG(t, n, sskG, indexes)
	if err != nil {
		return err
	}

	// Combiner informs all other party of (kb)^{-1}, and all party computes (kb)^{-1}*shareb as share of k^{-1}
	// Combiner broadcasts x coordinate of [k]G
	for i := uint(0); i < n; i++ {
		parties[i].Setr(xCoor)
	}

	for i := uint(0); i < n; i++ {
		parties[i].LocalSharekInv(kbInv)
	}

	return nil
}

// During online round, all metals construct their own signature share upon receiving the message
// Input: n, the number of parties
// Input: myGroup, the group we operate in
func genSignatureShare(n uint, myGroup group.Group, parties []partySign) {
	for i := uint(0); i < n; i++ {
		parties[i].LocalGenSignatureShare()
	}
}

// ECDSA threshold signature generation
// Input: t, the threshold parameter
// Input: nPrime, the number of parties involved in the final signature generation
// Input: myGroup, the group we operate in
// Input: parties, the parties of size n
// Input: msg, the message hash
// curve: curve, the curve we operate in
// Output: signature (r,s) or possible error
func sign(t, nPrime uint, myGroup group.Group, sharesk []secretsharing.Share, parties []partySign, preParties []partyPreSign, msg []byte, curve elliptic.Curve) (group.Scalar, group.Scalar, error) {

	// Local: Parties initiate the parameters
	for i := uint(0); i < nPrime; i++ {
		parties[i].LocalInit(i+1, myGroup, preParties[i])
		parties[i].Setss(sharesk[i].Share)
	}

	msgBig := hashToInt(msg, curve)
	msgByte := msgBig.Bytes()

	hashScalar := myGroup.NewScalar()
	errBinary := hashScalar.UnmarshalBinary(msgByte)
	if errBinary != nil {
		panic(errBinary)
	}
	// Every party gets the hash Scalar
	for i := uint(0); i < nPrime; i++ {
		parties[i].SetMSG(hashScalar)
	}

	// Parties generate signature online round 3
	genSignatureShare(nPrime, myGroup, parties)

	// A combiner interpolate the signature
	sigShares := make([]secretsharing.Share, nPrime)
	for i := uint(0); i < nPrime; i++ {
		sigShares[i].ID = parties[i].sharesig.ID
		sigShares[i].Share = parties[i].sharesig.Share.Copy()
	}
	s, err := secretsharing.New(parties[0].myGroup, t, nPrime)
	if err != nil {
		panic(err)
	}
	signature, err := s.Recover(sigShares)
	if err != nil {
		return nil, nil, err
	}
	return parties[0].r, signature, nil
}

func testECDSAThresholdSingle(t, n, nPrime uint, myGroup group.Group, curve elliptic.Curve, prv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) error {

	// Construct parties
	parties := make([]partyPreSign, n)

	// PreSign: Precomputation
	errPreSign := preSign(t, n, myGroup, parties)

	if errPreSign != nil {
		return errPreSign
	}

	// Sign the message

	// Construct parties for signing
	partiesSign := make([]partySign, n)

	// Core generates secret shares for every party
	sharesk := core(t, n, prv, myGroup, partiesSign, curve)

	msg := []byte("Cloudflare: meow meow")
	r, s, errSign := sign(t, nPrime, myGroup, sharesk, partiesSign, parties, msg, curve)
	if errSign != nil {
		return errSign
	}

	// Verify the signature
	errVerify := Verify(r, s, msg, pub)

	if errVerify != nil {
		return errVerify
	}

	return nil
}

func testECDSAThreshold(t *testing.T, threshold, n, nPrime uint, myGroup group.Group, curve elliptic.Curve) {
	prv, pub := genKey(curve)
	err := testECDSAThresholdSingle(threshold, n, nPrime, myGroup, curve, prv, pub)
	if n < 2*threshold+1 {
		if err == nil {
			t.Error("Less than 2t+1 parties should fail")
		}
	} else {
		if nPrime < 2*threshold+1 {
			if err == nil {
				t.Error("Signature generation should fail with less than 2t+1 parties")
			}
		} else {
			if err != nil {
				t.Error("Signature generation fail")
			}
		}
	}
}

func benchECDSAThreshold(b *testing.B, myGroup group.Group, curve elliptic.Curve) {

	prv, pub := genKey(curve)

	// Construct parties
	parties := make([]partyPreSign, benchn)

	// Bench PreSign
	b.Run(curve.Params().Name+"-PreSign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			errPreSign := preSign(benchThreshold, benchn, myGroup, parties)
			if errPreSign != nil {
				b.Error("Bench ECDSA TSS FAIL!")
			}
		}
	})

	// PreSign: Precomputation
	errPreSign := preSign(benchThreshold, benchn, myGroup, parties)

	if errPreSign != nil {
		b.Error("Bench ECDSA TSS Precomputation FAIL!")
	}

	// Construct parties for signing
	partiesSign := make([]partySign, benchn)
	// Core generates secret shares for every party
	sharesk := core(benchThreshold, benchn, prv, myGroup, partiesSign, curve)
	msg := []byte("Cloudflare: meow meow")

	// Bench Sign
	b.Run(curve.Params().Name+"-Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {

			r, s, errSign := sign(benchThreshold, benchnPrime, myGroup, sharesk, partiesSign, parties, msg, curve)
			if errSign != nil {
				b.Error("Bench ECDSA TSS FAIL!")
			}

			errVerify := Verify(r, s, msg, pub)
			if errVerify != nil {
				b.Error("Bench ECDSA TSS FAIL!")
			}
		}
	})

}

func TestECDSAThreshold(t *testing.T) {
	for threshold := uint(1); threshold <= testThreshold; threshold++ {
		for n := threshold + 1; n < 3*threshold+1; n++ {
			for nPrime := threshold + 1; nPrime <= n; nPrime++ {

				t.Run("ECDSATSS256", func(t *testing.T) {
					pubkeyCurve := elliptic.P256()
					curr_group := group.P256
					testECDSAThreshold(t, threshold, n, nPrime, curr_group, pubkeyCurve)
				})
				t.Run("ECDSATSS384", func(t *testing.T) {
					pubkeyCurve := elliptic.P384()
					curr_group := group.P384
					testECDSAThreshold(t, threshold, n, nPrime, curr_group, pubkeyCurve)
				})

				t.Run("ECDSATSS521", func(t *testing.T) {
					pubkeyCurve := elliptic.P521()
					curr_group := group.P521
					testECDSAThreshold(t, threshold, n, nPrime, curr_group, pubkeyCurve)
				})
			}
		}
	}
}

func BenchmarkECDSASign256(b *testing.B) {
	pubkeyCurve := elliptic.P256()
	curr_group := group.P256
	benchECDSAThreshold(b, curr_group, pubkeyCurve)

	pubkeyCurve = elliptic.P384()
	curr_group = group.P384
	benchECDSAThreshold(b, curr_group, pubkeyCurve)

	pubkeyCurve = elliptic.P521()
	curr_group = group.P521
	benchECDSAThreshold(b, curr_group, pubkeyCurve)

}
