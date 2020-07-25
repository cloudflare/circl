package api_test

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign/api"
)

func TestApi(t *testing.T) {
	allSchemes := api.AllSchemes()
	for _, scheme := range allSchemes {
		t.Logf("%v: %v\n", scheme.ID(), scheme.Name())
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

		if uint(len(packedPk)) != scheme.PublicKeySize() {
			t.Fatal()
		}

		packedSk, err := sk.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}

		if uint(len(packedSk)) != scheme.PrivateKeySize() {
			t.Fatal()
		}

		pk2, err := scheme.UnmarshalBinaryPublicKey(packedPk)
		if err != nil {
			t.Fatal(err)
		}

		sk2, err := scheme.UnmarshalBinaryPrivateKey(packedSk)
		if err != nil {
			t.Fatal(err)
		}

		if !sk.Equal(sk2) {
			t.Fatal()
		}

		if !pk.Equal(pk2) {
			t.Fatal()
		}

		msg := []byte(fmt.Sprintf("Signing with %s", scheme.Name()))
		sig := scheme.Sign(sk, msg, nil)

		if scheme.SignatureSize() != uint(len(sig)) {
			t.Fatal()
		}

		if !scheme.Verify(pk2, msg, sig, nil) {
			t.Fatal()
		}

		sig[0]++
		if scheme.Verify(pk2, msg, sig, nil) {
			t.Fatal()
		}

		scheme2 := api.SchemeByName(scheme.Name())
		if scheme2 == nil || scheme2 != scheme {
			t.Fatal()
		}

		if pk.Scheme() != scheme {
			t.Fatal()
		}

		if sk.Scheme() != scheme {
			t.Fatal()
		}
	}
}
