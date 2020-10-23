package schemes_test

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/kem/schemes"
)

func TestCaseSensitivity(t *testing.T) {
	if schemes.ByName("kyber512") != schemes.ByName("Kyber512") {
		t.Fatal()
	}
}

func TestApi(t *testing.T) {
	allSchemes := schemes.All()
	for _, scheme := range allSchemes {
		scheme := scheme
		t.Run(scheme.Name(), func(t *testing.T) {
			if scheme == nil {
				t.Fatal()
			}

			pk, sk, err := scheme.GenerateKey()
			if err != nil {
				t.Fatal()
			}

			packedPk, err := pk.MarshalBinary()
			if err != nil {
				t.Fatal()
			}

			if len(packedPk) != scheme.PublicKeySize() {
				t.Fatal()
			}

			packedSk, err := sk.MarshalBinary()
			if err != nil {
				t.Fatal()
			}

			if len(packedSk) != scheme.PrivateKeySize() {
				t.Fatal()
			}

			pk2, err := scheme.UnmarshalBinaryPublicKey(packedPk)
			if err != nil {
				t.Fatal()
			}

			sk2, err := scheme.UnmarshalBinaryPrivateKey(packedSk)
			if err != nil {
				t.Fatal()
			}

			if !sk.Equal(sk2) {
				t.Fatal()
			}

			if !pk.Equal(pk2) {
				t.Fatal()
			}

			ct, ss := scheme.Encapsulate(pk2)

			if len(ct) != scheme.CiphertextSize() {
				t.Fatal()
			}
			if len(ss) != scheme.SharedKeySize() {
				t.Fatal()
			}

			ss2 := scheme.Decapsulate(sk2, ct)
			if !bytes.Equal(ss, ss2) {
				t.Fatal()
			}
		})
	}
}
