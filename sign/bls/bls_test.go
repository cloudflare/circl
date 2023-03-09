package bls_test

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/sign/bls"
)

func TestSuite(t *testing.T) {
	t.Run("BLS12381G1", func(t *testing.T) { check[bls.G1](t) })

	t.Run("BLS12381G2", func(t *testing.T) { check[bls.G2](t) })
}

func check[K bls.KeyGroup](t *testing.T) {
	const testTimes = 1 << 7
	msg := []byte("BLS signing")
	salt := []byte{23, 23, 232, 32, 32}
	keyInfo := []byte{23, 23, 232, 32, 32}
	ikm := [32]byte{}

	for i := 0; i < testTimes; i++ {
		_, _ = rand.Reader.Read(ikm[:])

		priv, err := bls.KeyGen[K](ikm[:], salt, keyInfo)
		test.CheckNoErr(t, err, "failed to keygen")
		signature := bls.Sign(priv, msg)
		pub := priv.PublicKey()
		test.CheckOk(bls.Verify(pub, msg, signature), "failed verification", t)
	}
}
