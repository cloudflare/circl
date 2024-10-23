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
		checkIssue488(t, kem)
	}
}

func checkIssue488(t *testing.T, kem hpke.KEM) {
	scheme := kem.Scheme()
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	skBytes, err := sk.MarshalBinary()
	test.CheckNoErr(t, err, "marshal private key")
	pkBytes, err := pk.MarshalBinary()
	test.CheckNoErr(t, err, "marshal public key")

	t.Run(fmt.Sprintf("%v/PrivateKey", scheme.Name()), func(t *testing.T) {
		N := scheme.PrivateKeySize()
		buffer := make([]byte, N+1)
		copy(buffer, skBytes)

		// passing a buffer larger than the private key size should error (but no panic).
		_, err := scheme.UnmarshalBinaryPrivateKey(buffer[:N+1])
		test.CheckIsErr(t, err, "unmarshal private key should failed")

		// passing a buffer of the exact size must be correct.
		gotSk, err := scheme.UnmarshalBinaryPrivateKey(buffer[:N])
		test.CheckNoErr(t, err, "unmarshal private key shouldn't fail")
		test.CheckOk(sk.Equal(gotSk), "private keys are not equal", t)
	})

	t.Run(fmt.Sprintf("%v/PublicKey", scheme.Name()), func(t *testing.T) {
		N := scheme.PublicKeySize()
		buffer := make([]byte, N+1)
		copy(buffer, pkBytes)

		// passing a buffer larger than the public key size should error (but no panic).
		_, err := scheme.UnmarshalBinaryPublicKey(buffer[:N+1])
		test.CheckIsErr(t, err, "unmarshal public key should failed")

		gotPk, err := scheme.UnmarshalBinaryPublicKey(buffer[:N])
		test.CheckNoErr(t, err, "unmarshal public key shouldn't fail")
		test.CheckOk(pk.Equal(gotPk), "public keys are not equal", t)
	})
}
