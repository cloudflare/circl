package hpke_test

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/internal/test"
)

func TestKemKeysMarshal(t *testing.T) {
	for _, kem := range []hpke.KEM{
		hpke.KEM_P256_HKDF_SHA256,
		hpke.KEM_P384_HKDF_SHA384,
		hpke.KEM_P521_HKDF_SHA512,
		hpke.KEM_X25519_HKDF_SHA256,
		hpke.KEM_X448_HKDF_SHA512,
		hpke.KEM_X25519_KYBER768_DRAFT00,
	} {
		fixIssue488(t, kem)
	}
}

func fixIssue488(t *testing.T, kem hpke.KEM) {
	scheme := kem.Scheme()
	// Passing larger slices to UnmarshlBinary on keys causes panic.
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	t.Run(fmt.Sprintf("%v/PrivateKey", scheme.Name()), func(t *testing.T) {
		// setting a buffer larger than the private key.
		buffer := make([]byte, scheme.PrivateKeySize()+100)

		skBytes, err := sk.MarshalBinary()
		test.CheckNoErr(t, err, "marshal private key")

		copy(buffer, skBytes)

		gotSk, err := scheme.UnmarshalBinaryPrivateKey(buffer)
		test.CheckNoErr(t, err, "unmarshal private key")
		test.CheckOk(sk.Equal(gotSk), "private keys are not equal", t)
	})

	t.Run(fmt.Sprintf("%v/PublicKey", scheme.Name()), func(t *testing.T) {
		// setting a buffer larger than the public key.
		buffer := make([]byte, scheme.PublicKeySize()+100)

		pkBytes, err := pk.MarshalBinary()
		test.CheckNoErr(t, err, "marshal public key")

		copy(buffer, pkBytes)

		gotPk, err := scheme.UnmarshalBinaryPublicKey(buffer)
		test.CheckNoErr(t, err, "unmarshal public key")
		test.CheckOk(pk.Equal(gotPk), "public keys are not equal", t)
	})
}
