package ecdsaTSS

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/secretsharing"
)

const TestThreshold = 2
const BenchThreshold = 1
const Benchn = 3
const BenchnPrime = 3

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

func testECDSAThresholdSingle(t, n, nPrime uint, myGroup group.Group, curve elliptic.Curve, prv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) error {

	// Construct parties
	parties := make([]partyPreSign, n)

	// PreSign: Precomputation
	errPreSign := PreSign(t, n, myGroup, parties)

	if errPreSign != nil {
		return errPreSign
	}

	// Sign the message

	// Construct parties for signing
	partiesSign := make([]partySign, n)

	// Core generates secret shares for every party
	sharesk := core(t, n, prv, myGroup, partiesSign, curve)

	msg := []byte("Cloudflare: meow meow")
	r, s, errSign := Sign(t, nPrime, myGroup, sharesk, partiesSign, parties, msg, curve)
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
	parties := make([]partyPreSign, Benchn)

	// Bench PreSign
	b.Run(curve.Params().Name+"-PreSign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			errPreSign := PreSign(BenchThreshold, Benchn, myGroup, parties)
			if errPreSign != nil {
				b.Error("Bench ECDSA TSS FAIL!")
			}
		}
	})

	// PreSign: Precomputation
	errPreSign := PreSign(BenchThreshold, Benchn, myGroup, parties)

	if errPreSign != nil {
		b.Error("Bench ECDSA TSS Precomputation FAIL!")
	}

	// Construct parties for signing
	partiesSign := make([]partySign, Benchn)
	// Core generates secret shares for every party
	sharesk := core(BenchThreshold, Benchn, prv, myGroup, partiesSign, curve)
	msg := []byte("Cloudflare: meow meow")

	// Bench Sign
	b.Run(curve.Params().Name+"-Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {

			r, s, errSign := Sign(BenchThreshold, BenchnPrime, myGroup, sharesk, partiesSign, parties, msg, curve)
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
	for threshold := uint(1); threshold <= TestThreshold; threshold++ {
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
