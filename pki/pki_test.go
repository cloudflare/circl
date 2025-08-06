package pki_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/pki"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

func TestPEM(t *testing.T) {
	for _, scheme := range schemes.All() {
		t.Run(scheme.Name(), func(t *testing.T) {
			if scheme == nil {
				t.Fatal()
			}

			_, ok := scheme.(pki.CertificateScheme)
			if !ok {
				return
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
		})
	}
}

func testMLDSAHappy(t *testing.T, fn string) {
	t.Run(fn+" happy", func(t *testing.T) {
		err := testMLDSA(t, fn)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func testMLDSASad(t *testing.T, fn string) {
	t.Run(fn+" sad", func(t *testing.T) {
		err := testMLDSA(t, fn)
		if err == nil {
			t.Fatal("Expected error")
		}
	})
}

func testMLDSA(t *testing.T, fn string) error {
	pem, err := test.ReadGzip("testdata/" + fn)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := pki.UnmarshalPEMPrivateKey(pem)
	if err != nil {
		return err
	}

	seed := sk.(sign.Seeded).Seed()
	if seed == nil {
		return errors.New("seed not retained")
	}

	if !bytes.Equal(seed, []byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
		19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	}) {
		return errors.New("unexpected seed")
	}

	return nil
}

func TestMLDSA(t *testing.T) {
	// Tests taken from draft-ietf-lamps-dilithium-certificates-12
	for _, lvl := range []string{"44", "65", "87"} {
		for _, tpe := range []string{"seed", "both"} {
			testMLDSAHappy(t, fmt.Sprintf("ML-DSA-%s-%s.priv.gz", lvl, tpe))
		}
		testMLDSASad(t, fmt.Sprintf("ML-DSA-%s-expanded.priv.gz", lvl))
	}

	testMLDSASad(t, "bad-ML-DSA-44-1.priv.gz")
}
