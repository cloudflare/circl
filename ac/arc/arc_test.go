package arc

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func TestCompressed(t *testing.T) {
	id := SuiteP256
	s := id.getSuite()
	p := s.g.Params()

	t.Run("okCompressed", func(t *testing.T) {
		z := eltCom{s.g.RandomElement(rand.Reader)}
		test.CheckMarshal(t, &z, &eltCom{s.newElement()})

		enc, err := z.MarshalBinary()
		test.CheckNoErr(t, err, "error on marshalling")
		test.CheckOk(len(enc) == int(p.CompressedElementLength), "bad length", t)
	})

	t.Run("badCompressed", func(t *testing.T) {
		// Skip on groups that do not admit point compression.
		if p.CompressedElementLength == p.ElementLength {
			t.Skip()
		}

		// Fails when unmarshaling non-compressed points.
		x := s.g.RandomElement(rand.Reader)
		enc, err := x.MarshalBinary()
		test.CheckNoErr(t, err, "error on marshalling")
		test.CheckOk(uint(len(enc)) == p.ElementLength, "bad length", t)

		xx := eltCom{s.newElement()}
		err1 := xx.UnmarshalBinary(enc)
		test.CheckIsErr(t, err1, "should fail")
	})
}

func BenchmarkArc(b *testing.B) {
	b.Run(SuiteP256.String(), SuiteP256.benchmarkArc)
	b.Run(SuiteRistretto255.String(), SuiteRistretto255.benchmarkArc)
}

func (id SuiteID) benchmarkArc(b *testing.B) {
	reqContext := []byte("Credential for Alice")
	presContext := []byte("Presentation for example.com")
	priv := KeyGen(rand.Reader, id)
	pub := priv.PublicKey()

	fin, credReq := Request(rand.Reader, id, reqContext)
	credRes, err := Response(rand.Reader, &priv, &credReq)
	test.CheckNoErr(b, err, "failed Response")

	credential, err := Finalize(&fin, &credReq, credRes, &pub)
	test.CheckNoErr(b, err, "failed Finalize")

	const MaxPres = 1000
	state, err := NewState(credential, presContext, MaxPres)
	test.CheckNoErr(b, err, "failed NewState")
	nonce, pres, err := state.Present(rand.Reader)
	test.CheckNoErr(b, err, "failed Finalize")

	ok := Verify(&priv, pres, reqContext, presContext, *nonce, MaxPres)
	test.CheckOk(ok, "verify failed", b)

	b.Run("KeyGen", func(b *testing.B) {
		for range b.N {
			k := KeyGen(rand.Reader, id)
			_ = k.PublicKey()
		}
	})

	b.Run("Request", func(b *testing.B) {
		for range b.N {
			_, _ = Request(rand.Reader, id, reqContext)
		}
	})

	b.Run("Response", func(b *testing.B) {
		for range b.N {
			_, _ = Response(rand.Reader, &priv, &credReq)
		}
	})

	b.Run("Finalize", func(b *testing.B) {
		for range b.N {
			_, _ = Finalize(&fin, &credReq, credRes, &pub)
		}
	})

	b.Run("Present", func(b *testing.B) {
		for range b.N {
			s, _ := NewState(credential, presContext, MaxPres)
			_, _, _ = s.Present(rand.Reader)
		}
	})

	b.Run("Verify", func(b *testing.B) {
		for range b.N {
			_ = Verify(&priv, pres, reqContext, presContext, *nonce, MaxPres)
		}
	})
}
