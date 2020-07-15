package sign_test

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign"
)

func TestPEM(t *testing.T) {
	names := sign.ListSchemeNames()
	for _, name := range names {
		scheme := sign.SchemeByName(name)
		if scheme == nil {
			t.Fatal()
		}

		_, ok := scheme.(sign.CertificateScheme)
		if !ok {
			continue
		}

		pk, sk, err := scheme.GenerateKey()
		if err != nil {
			t.Fatal()
		}

		packedPk, err := sign.MarshalPEMPublicKey(pk)
		if err != nil {
			t.Fatal()
		}

		pk2, err := sign.UnmarshalPEMPublicKey(packedPk)
		if err != nil {
			t.Fatal()
		}
		if !sign.PublicKeysEqual(pk2, pk) {
			t.Fatal()
		}

		packedSk, err := sign.MarshalPEMPrivateKey(sk)
		if err != nil {
			t.Fatal()
		}

		sk2, err := sign.UnmarshalPEMPrivateKey(packedSk)
		if err != nil {
			t.Fatal()
		}

		if !sign.PrivateKeysEqual(sk2, sk) {
			t.Fatal()
		}
	}
}

func TestApi(t *testing.T) {
	names := sign.ListSchemeNames()
	for _, name := range names {
		scheme := sign.SchemeByName(name)
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
			t.Fatal()
		}

		if uint(len(packedSk)) != scheme.PrivateKeySize() {
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

		if !sign.PrivateKeysEqual(sk, sk2) {
			t.Fatal()
		}

		if !sign.PublicKeysEqual(pk, pk2) {
			t.Fatal()
		}

		msg := []byte(fmt.Sprintf("Signing with %s", name))
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

		if scheme.Name() != name {
			t.Fatal()
		}

		if pk.Scheme() != scheme {
			t.Fatal()
		}

		if sk.Scheme() != scheme {
			t.Fatal()
		}

		pk3 := sk.Public().(sign.PublicKey)
		if !sign.PublicKeysEqual(pk3, pk) {
			t.Fatal()
		}
	}
}
