package schemes_test

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

func TestCaseSensitivity(t *testing.T) {
	if schemes.ByName("ed25519") != schemes.ByName("Ed25519") {
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
			opts := &sign.SignatureOpts{}
			if scheme.SupportsContext() {
				opts.Context = "A context"
			}
			sig := scheme.Sign(sk, msg, opts)

			if scheme.SignatureSize() != len(sig) {
				t.Fatal()
			}

			if !scheme.Verify(pk2, msg, sig, opts) {
				t.Fatal()
			}

			if scheme.SupportsContext() {
				opts2 := opts
				opts2.Context = "Wrong context"
				if scheme.Verify(pk2, msg, sig, opts2) {
					t.Fatal()
				}
			}

			sig[0]++
			if scheme.Verify(pk2, msg, sig, opts) {
				t.Fatal()
			}

			scheme2 := schemes.ByName(scheme.Name())
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
