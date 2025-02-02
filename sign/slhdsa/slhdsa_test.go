package slhdsa_test

import (
	"crypto"
	"crypto/rand"
	"io"
	"testing"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/cloudflare/circl/xof"
)

var fastSign = [...]slhdsa.ID{
	slhdsa.SHA2_128f, slhdsa.SHAKE_128f,
	slhdsa.SHA2_192f, slhdsa.SHAKE_192f,
	slhdsa.SHA2_256f, slhdsa.SHAKE_256f,
}

var smallSign = [...]slhdsa.ID{
	slhdsa.SHA2_128s, slhdsa.SHAKE_128s,
	slhdsa.SHA2_192s, slhdsa.SHAKE_192s,
	slhdsa.SHA2_256s, slhdsa.SHAKE_256s,
}

func TestInnerFast(t *testing.T)  { slhdsa.InnerTest(t, fastSign[:]) }
func TestInnerSmall(t *testing.T) { slhdsa.InnerTest(t, smallSign[:]) }
func TestSlhdsaFast(t *testing.T) { testSlhdsa(t, fastSign[:]) }
func TestSlhdsaSmall(t *testing.T) {
	slhdsa.SkipLongTest(t)
	testSlhdsa(t, smallSign[:])
}

func testSlhdsa(t *testing.T, sigIDs []slhdsa.ID) {
	for _, id := range sigIDs {
		t.Run(id.String(), func(t *testing.T) {
			t.Run("Keys", func(t *testing.T) { testKeys(t, id) })
			t.Run("Sign", func(t *testing.T) { testSign(t, id) })
		})
	}
}

func testKeys(t *testing.T, id slhdsa.ID) {
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

func testSign(t *testing.T, id slhdsa.ID) {
	pub, priv, err := slhdsa.GenerateKey(rand.Reader, id)
	test.CheckNoErr(t, err, "GenerateKey failed")

	msg := []byte("Alice and Bob")
	sig, err := priv.Sign(rand.Reader, msg, nil)
	test.CheckNoErr(t, err, "Sign randomized failed")

	valid := slhdsa.Verify(&pub, slhdsa.NewMessage(msg), sig, nil)
	test.CheckOk(valid, "Verify failed", t)
}

func BenchmarkInnerFast(b *testing.B)  { slhdsa.BenchInner(b, fastSign[:]) }
func BenchmarkInnerSmall(b *testing.B) { slhdsa.BenchInner(b, smallSign[:]) }
func BenchmarkSlhdsaFast(b *testing.B) { benchmarkSlhdsa(b, fastSign[:]) }
func BenchmarkSlhdsaSmall(b *testing.B) {
	slhdsa.SkipLongTest(b)
	benchmarkSlhdsa(b, smallSign[:])
}

func BenchmarkPreHash(b *testing.B) {
	b.Run("WithHash", func(b *testing.B) {
		ph, err := slhdsa.NewPreHashWithHash(crypto.SHA512)
		test.CheckNoErr(b, err, "NewPreHashWithHash failed")
		benchmarkPreHash(b, ph)
	})
	b.Run("WithXof", func(b *testing.B) {
		ph, err := slhdsa.NewPreHashWithXof(xof.SHAKE256)
		test.CheckNoErr(b, err, "NewPreHashWithXof failed")
		benchmarkPreHash(b, ph)
	})
}

func benchmarkPreHash(b *testing.B, ph *slhdsa.PreHash) {
	s := sha3.NewShake128()
	for range b.N {
		_, err := io.Copy(ph, io.LimitReader(&s, 1024))
		test.CheckNoErr(b, err, "io.Copy failed")

		_, err = ph.BuildMessage()
		test.CheckNoErr(b, err, "BuildMessage failed")
	}
}

func benchmarkSlhdsa(b *testing.B, sigIDs []slhdsa.ID) {
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
