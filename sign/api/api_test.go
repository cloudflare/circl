package api_test

import (
	"crypto"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/api"
)

func TestApi(t *testing.T) {
	allSchemes := api.AllSchemes()
	for _, scheme := range allSchemes {
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
				t.Fatal(err)
			}

			if len(packedSk) != scheme.PrivateKeySize() {
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
			opts := &sign.SignatureOpts{
				Hash:    crypto.Hash(0),
				Context: "a context",
			}
			sig := scheme.Sign(sk, msg, opts)

			if scheme.SignatureSize() != len(sig) {
				t.Fatal()
			}

			if !scheme.Verify(pk2, msg, sig, opts) {
				t.Fatal()
			}

			sig[0]++
			if scheme.Verify(pk2, msg, sig, opts) {
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
		})
	}
}
