package hpke_test

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/internal/test"
)

func TestKemKeysExactLength(t *testing.T) {
	for _, kemID := range []hpke.KEM{
		hpke.KEM_P256_HKDF_SHA256,
		hpke.KEM_P384_HKDF_SHA384,
		hpke.KEM_P521_HKDF_SHA512,
		hpke.KEM_X25519_HKDF_SHA256,
		hpke.KEM_X448_HKDF_SHA512,
		hpke.KEM_X25519_KYBER768_DRAFT00,
	} {
		checkExactLengthUnmarshal(t, kemID)
	}
}

func checkExactLengthUnmarshal(t *testing.T, kemID hpke.KEM) {
	scheme := kemID.Scheme()
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	skBytes, err := sk.MarshalBinary()
	test.CheckNoErr(t, err, "marshal private key")
	pkBytes, err := pk.MarshalBinary()
	test.CheckNoErr(t, err, "marshal public key")

	t.Run(fmt.Sprintf("%v/PrivateKey", scheme.Name()), func(t *testing.T) {
		n := scheme.PrivateKeySize()
		buffer := make([]byte, n+1)
		copy(buffer, skBytes)

		_, err := scheme.UnmarshalBinaryPrivateKey(buffer[:n+1])
		test.CheckIsErr(t, err, "oversized private key must fail")

		gotSk, err := scheme.UnmarshalBinaryPrivateKey(buffer[:n])
		test.CheckNoErr(t, err, "exact-size private key must succeed")
		test.CheckOk(sk.Equal(gotSk), "private keys must match", t)
	})

	t.Run(fmt.Sprintf("%v/PublicKey", scheme.Name()), func(t *testing.T) {
		n := scheme.PublicKeySize()
		buffer := make([]byte, n+1)
		copy(buffer, pkBytes)

		_, err := scheme.UnmarshalBinaryPublicKey(buffer[:n+1])
		test.CheckIsErr(t, err, "oversized public key must fail")

		gotPk, err := scheme.UnmarshalBinaryPublicKey(buffer[:n])
		test.CheckNoErr(t, err, "exact-size public key must succeed")
		test.CheckOk(pk.Equal(gotPk), "public keys must match", t)
	})
}
