package slhdsa_test

import (
	"crypto/rand"
	"flag"
	"testing"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/sign/slhdsa"
)

var supportedParameters = [12]slhdsa.ParamID{
	slhdsa.ParamIDSHA2Small128,
	slhdsa.ParamIDSHAKESmall128,
	slhdsa.ParamIDSHA2Fast128,
	slhdsa.ParamIDSHAKEFast128,
	slhdsa.ParamIDSHA2Small192,
	slhdsa.ParamIDSHAKESmall192,
	slhdsa.ParamIDSHA2Fast192,
	slhdsa.ParamIDSHAKEFast192,
	slhdsa.ParamIDSHA2Small256,
	slhdsa.ParamIDSHAKESmall256,
	slhdsa.ParamIDSHA2Fast256,
	slhdsa.ParamIDSHAKEFast256,
}

// Indicates whether long tests should be run
var runLongTest = flag.Bool("long", false, "runs longer tests")

func TestSlhdsaLong(t *testing.T) {
	if !*runLongTest {
		t.Skip("Skipped one long test, add -long flag to run longer tests")
	}

	for _, paramID := range supportedParameters {
		t.Run(paramID.String(), func(t *testing.T) {
			t.Run("Keys", func(t *testing.T) { testKeys(t, paramID) })

			t.Run("Sign", func(t *testing.T) { testSign(t, paramID) })
		})
	}
}

func TestSlhdsa(t *testing.T) {
	t.Run("Keys", func(t *testing.T) {
		testKeys(t, slhdsa.ParamIDSHA2Fast128)
	})
	t.Run("PreHashSHA256", func(t *testing.T) {
		testSign(t, slhdsa.ParamIDSHA2Fast128)
	})
}

func testKeys(t *testing.T, id slhdsa.ParamID) {
	reader := sha3.NewShake128()

	reader.Reset()
	pub0, priv0, err := slhdsa.GenerateKey(&reader, id)
	test.CheckNoErr(t, err, "GenerateKey failed")

	reader.Reset()
	pub1, priv1, err := slhdsa.GenerateKey(&reader, id)
	test.CheckNoErr(t, err, "GenerateKey failed")

	test.CheckOk(priv0.Equal(&priv1), "private key not equal", t)
	test.CheckOk(pub0.Equal(&pub1), "public key not equal", t)

	test.CheckMarshal(t, &priv0, &priv1)
	test.CheckMarshal(t, &pub0, &pub1)

	scheme := id.Scheme()
	seed := make([]byte, scheme.SeedSize())
	pub2, priv2 := scheme.DeriveKey(seed)
	pub3, priv3 := scheme.DeriveKey(seed)

	test.CheckOk(priv2.Equal(priv3), "private key not equal", t)
	test.CheckOk(pub2.Equal(pub3), "public key not equal", t)
}

func testSign(t *testing.T, id slhdsa.ParamID) {
	msg := []byte("Alice and Bob")
	ctx := []byte("this is a context string")

	pk, sk, err := slhdsa.GenerateKey(rand.Reader, id)
	test.CheckNoErr(t, err, "keygen failed")

	m := slhdsa.NewMessagito(msg)
	test.CheckNoErr(t, err, "NewPreHashedMessage failed")

	sig, err := slhdsa.SignRandomized(&sk, rand.Reader, m, ctx)
	test.CheckNoErr(t, err, "Sign randomized failed")

	valid := slhdsa.Verify(&pk, m, sig, ctx)
	test.CheckOk(valid, "Verify failed", t)

	sig, err = slhdsa.SignDeterministic(&sk, m, ctx)
	test.CheckNoErr(t, err, "Sign deterministic failed")

	valid = slhdsa.Verify(&pk, m, sig, ctx)
	test.CheckOk(valid, "Verify failed", t)
}

func BenchmarkSlhdsa(b *testing.B) {
	for i := range supportedParameters {
		id := supportedParameters[i]

		b.Run(id.String(), func(b *testing.B) {
			b.Run("GenerateKey", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, _, _ = slhdsa.GenerateKey(rand.Reader, id)
				}
			})

			msg := []byte("Alice and Bob")
			ctx := []byte("this is a context string")
			pub, priv, err := slhdsa.GenerateKey(rand.Reader, id)
			test.CheckNoErr(b, err, "GenerateKey failed")
			b.Run("Sign", func(b *testing.B) {
				benchmarkSign(b, &pub, &priv, msg, ctx)
			})

		})
	}
}

func benchmarkSign(
	b *testing.B,
	pk *slhdsa.PublicKey,
	sk *slhdsa.PrivateKey,
	msg, ctx []byte,
) {
	m := slhdsa.NewMessagito(msg)

	sig, err := slhdsa.SignDeterministic(sk, m, ctx)
	test.CheckNoErr(b, err, "SignDeterministic failed")

	b.Run("SignRandomized", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = slhdsa.SignRandomized(sk, rand.Reader, m, ctx)
		}
	})
	b.Run("SignDeterministic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = slhdsa.SignDeterministic(sk, m, ctx)
		}
	})
	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = slhdsa.Verify(pk, m, sig, ctx)
		}
	})
}
