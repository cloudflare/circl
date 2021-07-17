package ff

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func randomFp12(t testing.TB) *Fp12 { return &Fp12{*randomFp6(t), *randomFp6(t)} }

func TestFp12(t *testing.T) {
	const testTimes = 1 << 10
	t.Run("no_alias", func(t *testing.T) {
		var want, got Fp12
		x := randomFp12(t)
		got.Set(x)
		got.Sqr(&got)
		want.Set(x)
		want.Mul(&want, &want)
		if !got.IsEqual(&want) {
			test.ReportError(t, got, want, x)
		}
	})
	t.Run("mul_inv", func(t *testing.T) {
		var z Fp12
		for i := 0; i < testTimes; i++ {
			x := randomFp12(t)
			y := randomFp12(t)

			// x*y*x^1 - y = 0
			z.Inv(x)
			z.Mul(&z, y)
			z.Mul(&z, x)
			z.Sub(&z, y)
			got := z.IsZero()
			want := true
			if got != want {
				test.ReportError(t, got, want, x, y)
			}
		}
	})
	t.Run("mul_sqr", func(t *testing.T) {
		var l0, l1, r0, r1 Fp12
		for i := 0; i < testTimes; i++ {
			x := randomFp12(t)
			y := randomFp12(t)

			// (x+y)(x-y) = (x^2-y^2)
			l0.Add(x, y)
			l1.Sub(x, y)
			l0.Mul(&l0, &l1)
			r0.Sqr(x)
			r1.Sqr(y)
			r0.Sub(&r0, &r1)
			got := &l0
			want := &r0
			if !got.IsEqual(want) {
				test.ReportError(t, got, want, x, y)
			}
		}
	})
	t.Run("serdes", func(t *testing.T) {
		var b Fp12
		for i := 0; i < testTimes; i++ {
			a := randomFp12(t)
			s := a.Bytes()
			err := b.SetBytes(s)
			test.CheckNoErr(t, err, "setbytes failed")
			if !b.IsEqual(a) {
				test.ReportError(t, a, b)
			}
		}
	})
}

func BenchmarkFp12(b *testing.B) {
	x := randomFp12(b)
	y := randomFp12(b)
	z := randomFp12(b)
	var n [32]byte
	mustRead(b, n[:])

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Add(x, y)
		}
	})
	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Mul(x, y)
		}
	})
	b.Run("Sqr", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Sqr(x)
		}
	})
	b.Run("Inv", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Inv(x)
		}
	})
	b.Run("Exp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Exp(x, n[:])
		}
	})
}

func mustRead(t testing.TB, b []byte) {
	n, err := rand.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(b) {
		t.Fatal("incomplete read")
	}
}
