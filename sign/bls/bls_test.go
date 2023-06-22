package bls_test

import (
	"bytes"
	"crypto/rand"
	"encoding"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/sign/bls"
)

func TestBls(t *testing.T) {
	t.Run("G1/API", testBls[bls.G1])
	t.Run("G2/API", testBls[bls.G2])
	t.Run("G1/Marshal", testMarshalKeys[bls.G1])
	t.Run("G2/Marshal", testMarshalKeys[bls.G2])
	t.Run("G1/Errors", testErrors[bls.G1])
	t.Run("G2/Errors", testErrors[bls.G2])
	t.Run("G1/Aggregation", testAggregation[bls.G1])
	t.Run("G2/Aggregation", testAggregation[bls.G2])
}

func testBls[K bls.KeyGroup](t *testing.T) {
	const testTimes = 1 << 7
	msg := []byte("hello world")
	keyInfo := []byte("KeyInfo for BLS")
	salt := [32]byte{}
	ikm := [32]byte{}
	_, _ = rand.Reader.Read(ikm[:])
	_, _ = rand.Reader.Read(salt[:])

	for i := 0; i < testTimes; i++ {
		_, _ = rand.Reader.Read(ikm[:])

		priv, err := bls.KeyGen[K](ikm[:], salt[:], keyInfo)
		test.CheckNoErr(t, err, "failed to keygen")
		signature := bls.Sign(priv, msg)
		pub := priv.Public().(*bls.PublicKey[K])
		test.CheckOk(bls.Verify(pub, msg, signature), "failed verification", t)
	}
}

func testMarshalKeys[K bls.KeyGroup](t *testing.T) {
	ikm := [32]byte{}
	priv, err := bls.KeyGen[K](ikm[:], nil, nil)
	test.CheckNoErr(t, err, "failed to keygen")
	pub := priv.PublicKey()

	auxPriv := new(bls.PrivateKey[K])
	auxPub := new(bls.PublicKey[K])

	t.Run("PrivateKey", func(t *testing.T) {
		testMarshal[K](t, priv, auxPriv)
		test.CheckOk(priv.Equal(auxPriv), "private keys do not match", t)
	})
	t.Run("PublicKey", func(t *testing.T) {
		testMarshal[K](t, pub, auxPub)
		test.CheckOk(pub.Equal(auxPub), "public keys do not match", t)
	})
}

func testMarshal[K bls.KeyGroup](
	t *testing.T,
	left, right interface {
		encoding.BinaryMarshaler
		encoding.BinaryUnmarshaler
	},
) {
	want, err := left.MarshalBinary()
	test.CheckNoErr(t, err, "failed to marshal")

	err = right.UnmarshalBinary(want)
	test.CheckNoErr(t, err, "failed to unmarshal")

	got, err := right.MarshalBinary()
	test.CheckNoErr(t, err, "failed to marshal")

	if !bytes.Equal(got, want) {
		test.ReportError(t, got, want)
	}
}

func testErrors[K bls.KeyGroup](t *testing.T) {
	// Short IKM
	_, err := bls.KeyGen[K](nil, nil, nil)
	test.CheckIsErr(t, err, "should fail: short ikm")

	// Bad Signature size
	ikm := [32]byte{}
	priv, err := bls.KeyGen[K](ikm[:], nil, nil)
	test.CheckNoErr(t, err, "failed to keygen")
	pub := priv.PublicKey()
	test.CheckOk(bls.Verify(pub, nil, nil) == false, "should fail: bad signature", t)
}

func testAggregation[K bls.KeyGroup](t *testing.T) {
	const N = 3

	ikm := [32]byte{}
	_, _ = rand.Reader.Read(ikm[:])

	msgs := make([][]byte, N)
	sigs := make([]bls.Signature, N)
	pubKeys := make([]*bls.PublicKey[K], N)

	for i := range sigs {
		priv, err := bls.KeyGen[K](ikm[:], nil, nil)
		test.CheckNoErr(t, err, "failed to keygen")
		pubKeys[i] = priv.PublicKey()

		msgs[i] = []byte(fmt.Sprintf("Message number: %v", i))
		sigs[i] = bls.Sign(priv, msgs[i])
	}

	aggSig, err := bls.Aggregate(*new(K), sigs)
	test.CheckNoErr(t, err, "failed to aggregate")

	ok := bls.VerifyAggregate(pubKeys, msgs, aggSig)
	test.CheckOk(ok, "failed to verify aggregated signature", t)
}

func BenchmarkBls(b *testing.B) {
	b.Run("G1", benchmarkBls[bls.G1])
	b.Run("G2", benchmarkBls[bls.G2])
}

func benchmarkBls[K bls.KeyGroup](b *testing.B) {
	msg := []byte("hello world")
	keyInfo := []byte("KeyInfo for BLS")
	salt := [32]byte{}
	ikm := [32]byte{}
	_, _ = rand.Reader.Read(ikm[:])
	_, _ = rand.Reader.Read(salt[:])

	priv, _ := bls.KeyGen[K](ikm[:], salt[:], keyInfo)

	const N = 3
	msgs := make([][]byte, N)
	sigs := make([]bls.Signature, N)
	pubKeys := make([]*bls.PublicKey[K], N)

	for i := range sigs {
		pubKeys[i] = priv.PublicKey()

		msgs[i] = []byte(fmt.Sprintf("Message number: %v", i))
		sigs[i] = bls.Sign(priv, msgs[i])
	}

	b.Run("Keygen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = rand.Reader.Read(ikm[:])
			_, _ = bls.KeyGen[K](ikm[:], salt[:], keyInfo)
		}
	})

	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = bls.Sign(priv, msg)
		}
	})

	b.Run("Verify", func(b *testing.B) {
		pub := priv.PublicKey()
		signature := bls.Sign(priv, msg)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			bls.Verify(pub, msg, signature)
		}
	})

	b.Run("Aggregate3", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = bls.Aggregate(*new(K), sigs)
		}
	})

	b.Run("VerifyAggregate3", func(b *testing.B) {
		aggSig, _ := bls.Aggregate(*new(K), sigs)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = bls.VerifyAggregate(pubKeys, msgs, aggSig)
		}
	})
}
