package ff

import (
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func randomFp2() *Fp2 {
	return &Fp2{
		*randomFp(),
		*randomFp(),
	}
}

func TestFp2(t *testing.T) {
	const testTimes = 1 << 10
	t.Run("no_alias", func(t *testing.T) {
		var want, got Fp2
		x := randomFp2()
		got.Set(x)
		got.Sqr(&got)
		want.Set(x)
		want.Mul(&want, &want)
		if !got.IsEqual(&want) {
			test.ReportError(t, got, want, x)
		}
	})
	t.Run("mul_inv", func(t *testing.T) {
		var z Fp2
		for i := 0; i < testTimes; i++ {
			x := randomFp2()
			y := randomFp2()

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
		var l0, l1, r0, r1 Fp2
		for i := 0; i < testTimes; i++ {
			x := randomFp2()
			y := randomFp2()

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
		var b Fp2
		for i := 0; i < testTimes; i++ {
			a := randomFp2()
			s := a.Bytes()
			b.SetBytes(s)
			if !b.IsEqual(a) {
				test.ReportError(t, a, b)
			}
		}
	})
}

func BenchmarkFp2(b *testing.B) {
	x := randomFp2()
	y := randomFp2()
	z := randomFp2()
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
