package bbs_test

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/sign/bbs"
)

func TestConstants(t *testing.T) {
	test.CheckOk(
		bbs.PublicKeySize == bls12381.G2SizeCompressed,
		"wrong PublicKeySize", t)
	test.CheckOk(
		bbs.PrivateKeySize == bls12381.ScalarSize,
		"wrong PrivateKeySize", t)
	test.CheckOk(
		bbs.SignatureSize == bls12381.G1SizeCompressed+bls12381.ScalarSize,
		"wrong SignatureSize", t)
}

func TestBBS(t *testing.T) {
	t.Run("BLS12381Shake256", func(t *testing.T) { testBBS(t, bbs.SuiteBLS12381Shake256) })
	t.Run("BLS12381Sha256", func(t *testing.T) { testBBS(t, bbs.SuiteBLS12381Sha256) })
}

func testBBS(t *testing.T, suite bbs.SuiteID) {
	var ikm [32]byte
	_, err := rand.Read(ikm[:])
	test.CheckNoErr(t, err, "failed rand.Read")

	keyInfo := []byte("Key Information")
	keyDst := []byte("Domain separation Tag")

	key, err := bbs.KeyGen(suite, ikm[:], keyInfo, keyDst)
	test.CheckNoErr(t, err, "failed KeyGen")

	pub := key.PublicKey()
	messages := [][]byte{
		[]byte("hero: Spider-Man"),
		[]byte("name: Peter Parker"),
		[]byte("age: 19"),
		[]byte("city: New York"),
		[]byte("lemma: with great power comes great responsibility"),
	}

	sOpts := bbs.SignOptions{ID: suite, Header: []byte("signature header")}
	sig := bbs.Sign(key, messages, sOpts)
	valid := bbs.Verify(pub, &sig, messages, sOpts)
	test.CheckOk(valid, "failed Verify", t)

	choices, err := bbs.Disclose(messages, []uint{0, 3, 4})
	test.CheckNoErr(t, err, "failed Disclose")

	pOpts := bbs.ProveOptions{[]byte("presentation header"), sOpts}
	proof, disclosed, err := bbs.Prove(rand.Reader, pub, &sig, choices, pOpts)
	test.CheckNoErr(t, err, "failed Prove")

	valid = bbs.VerifyProof(pub, proof, disclosed, pOpts)
	test.CheckOk(valid, "failed VerifyProof", t)

	test.CheckMarshal(t, key, new(bbs.PrivateKey))
	test.CheckMarshal(t, pub, new(bbs.PublicKey))
	test.CheckMarshal(t, &sig, new(bbs.Signature))
	test.CheckMarshal(t, proof, new(bbs.Proof))
}

func BenchmarkBBS(b *testing.B) {
	b.Run("BLS12381Shake256", func(b *testing.B) { benchmarkBBS(b, bbs.SuiteBLS12381Shake256) })
	b.Run("BLS12381Sha256", func(b *testing.B) { benchmarkBBS(b, bbs.SuiteBLS12381Sha256) })
}

func benchmarkBBS(b *testing.B, suite bbs.SuiteID) {
	var ikm [32]byte
	_, err := rand.Read(ikm[:])
	test.CheckNoErr(b, err, "failed rand Read")

	keyInfo := []byte("Key Information")
	keyDst := []byte("Domain separation Tag")

	key, err := bbs.KeyGen(suite, ikm[:], keyInfo, keyDst)
	test.CheckNoErr(b, err, "failed KeyGen")

	pub := key.PublicKey()
	messages := [][]byte{
		[]byte("hero: Spider-Man"),
		[]byte("name: Peter Parker"),
		[]byte("age: 19"),
		[]byte("city: New York"),
		[]byte("lemma: with great power comes great responsibility"),
	}

	sOpts := bbs.SignOptions{ID: suite, Header: []byte("signature header")}
	sig := bbs.Sign(key, messages, sOpts)
	valid := bbs.Verify(pub, &sig, messages, sOpts)
	test.CheckOk(valid, "failed Verify", b)

	choices, err := bbs.Disclose(messages, []uint{0, 3, 4})
	test.CheckNoErr(b, err, "failed Disclose")

	pOpts := bbs.ProveOptions{[]byte("presentation header"), sOpts}
	proof, disclosed, err := bbs.Prove(rand.Reader, pub, &sig, choices, pOpts)
	test.CheckNoErr(b, err, "failed Prove")

	valid = bbs.VerifyProof(pub, proof, disclosed, pOpts)
	test.CheckOk(valid, "failed VerifyProof", b)

	b.Run("KeyGen", func(b *testing.B) {
		for range b.N {
			key, _ = bbs.KeyGen(suite, ikm[:], keyInfo, keyDst)
			_ = key.Public()
		}
	})
	b.Run("Sign", func(b *testing.B) {
		for range b.N {
			_ = bbs.Sign(key, messages, sOpts)
		}
	})
	b.Run("Verify", func(b *testing.B) {
		for range b.N {
			_ = bbs.Verify(pub, &sig, messages, sOpts)
		}
	})
	b.Run("Prove", func(b *testing.B) {
		for range b.N {
			_, _, _ = bbs.Prove(rand.Reader, pub, &sig, choices, pOpts)
		}
	})
	b.Run("VerifyProof", func(b *testing.B) {
		for range b.N {
			_ = bbs.VerifyProof(pub, proof, disclosed, pOpts)
		}
	})
}
