package pki_test

import (
	"testing"

	"github.com/cloudflare/circl/pki"
	"github.com/cloudflare/circl/sign/api"
)

func TestPEM(t *testing.T) {
	for _, scheme := range api.AllSchemes() {
		t.Logf("%v: %v\n", scheme.ID(), scheme.Name())
		if scheme == nil {
			t.Fatal()
		}

		_, ok := scheme.(pki.CertificateScheme)
		if !ok {
			continue
		}

		pk, sk, err := scheme.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}

		packedPk, err := pki.MarshalPEMPublicKey(pk)
		if err != nil {
			t.Fatal(err)
		}

		pk2, err := pki.UnmarshalPEMPublicKey(packedPk)
		if err != nil {
			t.Fatal(err)
		}
		if !pk.Equal(pk2) {
			t.Fatal()
		}

		packedSk, err := pki.MarshalPEMPrivateKey(sk)
		if err != nil {
			t.Fatal(err)
		}

		sk2, err := pki.UnmarshalPEMPrivateKey(packedSk)
		if err != nil {
			t.Fatal(err)
		}

		if !sk.Equal(sk2) {
			t.Fatal()
		}
	}
}
