package slhdsa_test

import (
	"crypto/rand"
	"flag"
	"testing"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/sign/slhdsa"
)

var fastSign = [...]slhdsa.ParamID{
	slhdsa.ParamIDSHA2Fast128,
	slhdsa.ParamIDSHAKEFast128,
	slhdsa.ParamIDSHA2Fast192,
	slhdsa.ParamIDSHAKEFast192,
	slhdsa.ParamIDSHA2Fast256,
	slhdsa.ParamIDSHAKEFast256,
}

var smallSign = [...]slhdsa.ParamID{
	slhdsa.ParamIDSHA2Small128,
	slhdsa.ParamIDSHAKESmall128,
	slhdsa.ParamIDSHA2Small192,
	slhdsa.ParamIDSHAKESmall192,
	slhdsa.ParamIDSHA2Small256,
	slhdsa.ParamIDSHAKESmall256,
}

// Indicates whether long tests should be run
var runLongTest = flag.Bool("long", false, "sign/slhdsa: runs longer tests and benchmark")

const skipTestMsg = "Skipped one long test, add -long flag to run longer tests"

func TestSlhdsaFast(t *testing.T) { testSlhdsa(t, fastSign[:]) }
func TestSlhdsaSmall(t *testing.T) {
	if !*runLongTest {
		t.Skip(skipTestMsg)
	}

	testSlhdsa(t, smallSign[:])
}

func TestInnerFast(t *testing.T) {
	if !*runLongTest {
		t.Skip(skipTestMsg)
	}

	slhdsa.InnerTest(t, fastSign[:])
}

func TestInnerSmall(t *testing.T) {
	if !*runLongTest {
		t.Skip(skipTestMsg)
	}

	slhdsa.InnerTest(t, smallSign[:])
}

func testSlhdsa(t *testing.T, sigIDs []slhdsa.ParamID) {
	for _, id := range sigIDs {
		t.Run(id.String(), func(t *testing.T) {
			t.Run("Keys", func(t *testing.T) { testKeys(t, id) })
			t.Run("Sign", func(t *testing.T) { testSign(t, id) })
		})
	}
}

func testKeys(t *testing.T, id slhdsa.ParamID) {
	reader := sha3.NewShake128()

	reader.Reset()
	pub0, priv0, err := slhdsa.GenerateKey(&reader, id)
	test.CheckNoErr(t, err, "GenerateKey failed")

	reader.Reset()
	pub1, priv1, err := slhdsa.GenerateKey(&reader, id)
	test.CheckNoErr(t, err, "GenerateKey failed")

	test.CheckOk(pub0.Equal(pub1), "public key not equal", t)
	test.CheckOk(priv0.Equal(priv1), "private key not equal", t)

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
	pub, priv, err := slhdsa.GenerateKey(rand.Reader, id)
	test.CheckNoErr(t, err, "GenerateKey failed")

	msg := []byte("Alice and Bob")
	sig, err := priv.Sign(rand.Reader, msg, nil)
	test.CheckNoErr(t, err, "Sign randomized failed")

	valid := slhdsa.Verify(&pub, slhdsa.NewMessage(msg), sig, nil)
	test.CheckOk(valid, "Verify failed", t)
}

func BenchmarkSlhdsaFast(b *testing.B) { benchmarkSlhdsa(b, fastSign[:]) }

func BenchmarkSlhdsaSmall(b *testing.B) {
	if !*runLongTest {
		b.Skip(skipTestMsg)
	}

	benchmarkSlhdsa(b, smallSign[:])
}

func BenchmarkInnerFast(b *testing.B) {
	if !*runLongTest {
		b.Skip(skipTestMsg)
	}

	slhdsa.InnerBenchmark(b, fastSign[:])
}

func BenchmarkInnerSmall(b *testing.B) {
	if !*runLongTest {
		b.Skip(skipTestMsg)
	}

	slhdsa.InnerBenchmark(b, smallSign[:])
}

func benchmarkSlhdsa(b *testing.B, sigIDs []slhdsa.ParamID) {
	msg := slhdsa.NewMessage([]byte("Alice and Bob"))
	ctx := []byte("this is a context string")

	for _, id := range sigIDs {
		pub, priv, err := slhdsa.GenerateKey(rand.Reader, id)
		test.CheckNoErr(b, err, "GenerateKey failed")

		sig, err := slhdsa.SignDeterministic(&priv, msg, ctx)
		test.CheckNoErr(b, err, "SignDeterministic failed")

		b.Run(id.String(), func(b *testing.B) {
			b.Run("GenerateKey", func(b *testing.B) {
				for range b.N {
					_, _, _ = slhdsa.GenerateKey(rand.Reader, id)
				}
			})
			b.Run("SignRandomized", func(b *testing.B) {
				for range b.N {
					_, _ = slhdsa.SignRandomized(&priv, rand.Reader, msg, ctx)
				}
			})
			b.Run("SignDeterministic", func(b *testing.B) {
				for range b.N {
					_, _ = slhdsa.SignDeterministic(&priv, msg, ctx)
				}
			})
			b.Run("Verify", func(b *testing.B) {
				for range b.N {
					_ = slhdsa.Verify(&pub, msg, sig, ctx)
				}
			})
		})
	}
}
