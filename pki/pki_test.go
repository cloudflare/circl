package pki_test

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
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

func TestUnmarshalPEMNoBlock(t *testing.T) {
	for _, in := range [][]byte{nil, {}, []byte("not pem"), []byte("-----BEGIN GARBAGE")} {
		if _, err := pki.UnmarshalPEMPublicKey(in); err == nil {
			t.Errorf("UnmarshalPEMPublicKey(%q) expected error, got nil", in)
		}
		if _, err := pki.UnmarshalPEMPrivateKey(in); err == nil {
			t.Errorf("UnmarshalPEMPrivateKey(%q) expected error, got nil", in)
		}
	}
}

func TestUnmarshalAlgorithmParameters(t *testing.T) {
	// RFC 8410 and RFC 9881 require the AlgorithmIdentifier parameters to be
	// absent. Re-encode valid keys with an ASN.1 NULL parameter.
	null := asn1.RawValue{FullBytes: asn1.NullBytes}
	for _, scheme := range schemes.All() {
		cert, ok := scheme.(pki.CertificateScheme)
		if !ok {
			continue
		}
		t.Run(scheme.Name(), func(t *testing.T) {
			pk, sk, err := scheme.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}

			packedPk, err := pk.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			spki, err := asn1.Marshal(struct {
				pkix.AlgorithmIdentifier
				asn1.BitString
			}{
				pkix.AlgorithmIdentifier{Algorithm: cert.Oid(), Parameters: null},
				asn1.BitString{Bytes: packedPk, BitLength: len(packedPk) * 8},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = pki.UnmarshalPKIXPublicKey(spki); err == nil {
				t.Error("UnmarshalPKIXPublicKey accepted algorithm parameters")
			}

			packedSk, err := pki.MarshalPKIXPrivateKey(sk)
			if err != nil {
				t.Fatal(err)
			}
			var priv struct {
				Version    int
				Algorithm  pkix.AlgorithmIdentifier
				PrivateKey []byte
			}
			if _, err = asn1.Unmarshal(packedSk, &priv); err != nil {
				t.Fatal(err)
			}
			priv.Algorithm.Parameters = null
			packedSk, err = asn1.Marshal(priv)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pki.UnmarshalPKIXPrivateKey(packedSk); err == nil {
				t.Error("UnmarshalPKIXPrivateKey accepted algorithm parameters")
			}
		})
	}
}
