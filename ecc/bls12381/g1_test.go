package bls12381

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func randomScalar(t testing.TB) *Scalar {
	s := &Scalar{}
	err := s.Random(rand.Reader)
	test.CheckNoErr(t, err, "random scalar")
	return s
}

func randomG1(t testing.TB) *G1 {
	var P G1
	k := randomScalar(t)
	P.ScalarMult(k, G1Generator())
	if !P.IsOnCurve() {
		t.Helper()
		t.Fatal("not on curve")
	}
	return &P
}

func TestG1Add(t *testing.T) {
	const testTimes = 1 << 6
	var Q, R G1
	for i := 0; i < testTimes; i++ {
		P := randomG1(t)
		Q.Set(P)
		R.Set(P)
		R.Add(&R, &R)
		R.Neg()
		Q.Double()
		Q.Neg()
		got := R
		want := Q
		if !got.IsEqual(&want) {
			test.ReportError(t, got, want, P)
		}
	}
}

func TestG1ScalarMult(t *testing.T) {
	const testTimes = 1 << 6
	var Q G1
	for i := 0; i < testTimes; i++ {
		P := randomG1(t)
		k := randomScalar(t)
		Q.ScalarMult(k, P)
		Q.toAffine()
		got := Q.IsOnG1()
		want := true
		if got != want {
			test.ReportError(t, got, want, P, k)
		}
	}
}

func TestG1Hash(t *testing.T) {
	const testTimes = 1 << 8

	for _, e := range [...]struct {
		Name string
		Enc  func(p *G1, input, dst []byte)
	}{
		{"Encode", func(p *G1, input, dst []byte) { p.Encode(input, dst) }},
		{"Hash", func(p *G1, input, dst []byte) { p.Hash(input, dst) }},
	} {
		var msg, dst [4]byte
		var p G1
		t.Run(e.Name, func(t *testing.T) {
			for i := 0; i < testTimes; i++ {
				_, _ = rand.Read(msg[:])
				_, _ = rand.Read(dst[:])
				e.Enc(&p, msg[:], dst[:])

				got := p.isRTorsion()
				want := true
				if got != want {
					test.ReportError(t, got, want, e.Name, msg, dst)
				}
			}
		})
	}
}

func BenchmarkG1(b *testing.B) {
	P := randomG1(b)
	Q := randomG1(b)
	k := randomScalar(b)
	var msg, dst [4]byte
	_, _ = rand.Read(msg[:])
	_, _ = rand.Read(dst[:])

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.Add(P, Q)
		}
	})
	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.ScalarMult(k, P)
		}
	})
	b.Run("Hash", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.Hash(msg[:], dst[:])
		}
	})
}

func TestG1Serial(t *testing.T) {
	testTimes := 1 << 6
	for i := 0; i < testTimes; i++ {
		P := randomG1(t)
		var Q G1
		b := P.Bytes()
		err := Q.SetBytes(b)
		if err != nil {
			t.Fatal("failure to deserialize")
		}
		if !Q.IsEqual(P) {
			t.Fatal("deserialization wrong point")
		}
	}
}

func TestG1Affinize(t *testing.T) {
	N := 20
	testTimes := 1 << 6
	g1 := make([]*G1, N)
	g2 := make([]*G1, N)
	for i := 0; i < testTimes; i++ {
		for j := 0; j < N; j++ {
			g1[j] = randomG1(t)
			g2[j] = &G1{}
			g2[j].Set(g1[j])
		}
		affinize(g2)
		for j := 0; j < N; j++ {
			g1[j].toAffine()
			if !g1[j].IsEqual(g2[j]) {
				t.Fatal("failure to preserve points")
			}
			if g2[j].z.IsEqual(&g1[j].z) != 1 {
				t.Fatal("failure to make affine")
			}
		}
	}
}
