package slhdsa_test

import (
	"crypto/rand"
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

var supportedPrehashIDs = [5]slhdsa.PreHashID{
	slhdsa.NoPreHash,
	slhdsa.PreHashSHA256,
	slhdsa.PreHashSHA512,
	slhdsa.PreHashSHAKE128,
	slhdsa.PreHashSHAKE256,
}

func TestSlhdsa(t *testing.T) {
	for i := range supportedParameters {
		id := supportedParameters[i]

		t.Run(id.Name(), func(t *testing.T) {
			t.Run("Keys", func(t *testing.T) { testKeys(t, id) })

			for j := range supportedPrehashIDs {
				ph := supportedPrehashIDs[j]
				msg := []byte("Alice and Bob")
				ctx := []byte("this is a context string")
				pub, priv, err := slhdsa.GenerateKey(rand.Reader, id)
				test.CheckNoErr(t, err, "keygen failed")

				t.Run("Sign/"+ph.String(), func(t *testing.T) {
					testSign(t, &pub, &priv, msg, ctx, ph)
				})
			}
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

	test.CheckOk(priv0.Equal(&priv1), "private key not equal", t)
	test.CheckOk(pub0.Equal(&pub1), "public key not equal", t)

	test.CheckMarshal(t, &priv0, &priv1)
	test.CheckMarshal(t, &pub0, &pub1)

	seed := make([]byte, id.SeedSize())
	pub2, priv2 := id.DeriveKey(seed)
	pub3, priv3 := id.DeriveKey(seed)

	test.CheckOk(priv2.Equal(priv3), "private key not equal", t)
	test.CheckOk(pub2.Equal(pub3), "public key not equal", t)
}

func testSign(
	t *testing.T,
	pk *slhdsa.PublicKey,
	sk *slhdsa.PrivateKey,
	msg, ctx []byte,
	ph slhdsa.PreHashID,
) {
	m, err := slhdsa.NewMessageWithPreHash(ph)
	test.CheckNoErr(t, err, "NewMessageWithPreHash failed")

	_, err = m.Write(msg)
	test.CheckNoErr(t, err, "Write message failed")

	sig, err := sk.SignRandomized(rand.Reader, &m, ctx)
	test.CheckNoErr(t, err, "SignRandomized failed")

	valid := slhdsa.Verify(pk, &m, ctx, sig)
	test.CheckOk(valid, "Verify failed", t)

	sig, err = sk.SignDeterministic(&m, ctx)
	test.CheckNoErr(t, err, "SignDeterministic failed")

	valid = slhdsa.Verify(pk, &m, ctx, sig)
	test.CheckOk(valid, "Verify failed", t)
}

func BenchmarkSlhdsa(b *testing.B) {
	for i := range supportedParameters {
		id := supportedParameters[i]

		b.Run(id.Name(), func(b *testing.B) {
			b.Run("GenerateKey", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, _, _ = slhdsa.GenerateKey(rand.Reader, id)
				}
			})

			for j := range supportedPrehashIDs {
				ph := supportedPrehashIDs[j]
				msg := []byte("Alice and Bob")
				ctx := []byte("this is a context string")
				pub, priv, err := slhdsa.GenerateKey(rand.Reader, id)
				test.CheckNoErr(b, err, "GenerateKey failed")

				b.Run(ph.String(), func(b *testing.B) {
					benchmarkSign(b, &pub, &priv, msg, ctx, ph)
				})
			}
		})
	}
}

func benchmarkSign(
	b *testing.B,
	pk *slhdsa.PublicKey,
	sk *slhdsa.PrivateKey,
	msg, ctx []byte,
	ph slhdsa.PreHashID,
) {
	m, err := slhdsa.NewMessageWithPreHash(ph)
	test.CheckNoErr(b, err, "NewMessageWithPreHash failed")

	_, err = m.Write(msg)
	test.CheckNoErr(b, err, "Write message failed")

	sig, err := sk.SignRandomized(rand.Reader, &m, ctx)
	test.CheckNoErr(b, err, "SignRandomized failed")

	b.Run("SignRandomized", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = sk.SignRandomized(rand.Reader, &m, ctx)
		}
	})
	b.Run("SignDeterministic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = sk.SignDeterministic(&m, ctx)
		}
	})
	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = slhdsa.Verify(pk, &m, ctx, sig)
		}
	})
}
