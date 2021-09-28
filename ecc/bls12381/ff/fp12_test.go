package ff

import (
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func randomFp12(t testing.TB) *Fp12 { return &Fp12{*randomFp6(t), *randomFp6(t)} }

func TestFp12(t *testing.T) {
	const testTimes = 1 << 8
	t.Run("no_alias", func(t *testing.T) {
		var want, got Fp12
		x := randomFp12(t)
		got = *x
		got.Sqr(&got)
		want = *x
		want.Mul(&want, &want)
		if got.IsEqual(&want) == 0 {
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
			want := 1
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
			if got.IsEqual(want) == 0 {
				test.ReportError(t, got, want, x, y)
			}
		}
	})
	t.Run("marshal", func(t *testing.T) {
		var b Fp12
		for i := 0; i < testTimes; i++ {
			a := randomFp12(t)
			s, err := a.MarshalBinary()
			test.CheckNoErr(t, err, "MarshalBinary failed")
			err = b.UnmarshalBinary(s)
			test.CheckNoErr(t, err, "UnmarshalBinary failed")
			if b.IsEqual(a) == 0 {
				test.ReportError(t, a, b)
			}
		}
	})
	t.Run("frobenius", func(t *testing.T) {
		var got, want Fp12
		p := FpOrder()
		for i := 0; i < testTimes; i++ {
			x := randomFp12(t)

			// Frob(x) == x^p
			got.Frob(x)
			want.Exp(x, p)

			if got.IsEqual(&want) == 0 {
				test.ReportError(t, got, want, x)
			}
		}
	})
}

func BenchmarkFp12(b *testing.B) {
	x := randomFp12(b)
	y := randomFp12(b)
	z := randomFp12(b)

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
}
