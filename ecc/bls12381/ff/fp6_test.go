package ff

import (
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func randomFp6(t testing.TB) *Fp6 { return &Fp6{*randomFp2(t), *randomFp2(t), *randomFp2(t)} }

// expVarTime calculates z=x^n, where n is the exponent in big-endian order.
func expVarTime(z, x *Fp6, n []byte) {
	zz := new(Fp6)
	zz.SetOne()
	N := 8 * len(n)
	for i := 0; i < N; i++ {
		zz.Sqr(zz)
		bit := 0x1 & (n[i/8] >> uint(7-i%8))
		if bit != 0 {
			zz.Mul(zz, x)
		}
	}
	*z = *zz
}

func TestFp6(t *testing.T) {
	const testTimes = 1 << 10
	t.Run("no_alias", func(t *testing.T) {
		var want, got Fp6
		x := randomFp6(t)
		got = *x
		got.Sqr(&got)
		want = *x
		want.Mul(&want, &want)
		if got.IsEqual(&want) == 0 {
			test.ReportError(t, got, want, x)
		}
	})
	t.Run("mul_inv", func(t *testing.T) {
		var z Fp6
		for i := 0; i < testTimes; i++ {
			x := randomFp6(t)
			y := randomFp6(t)

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
		var l0, l1, r0, r1 Fp6
		for i := 0; i < testTimes; i++ {
			x := randomFp6(t)
			y := randomFp6(t)

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
	t.Run("frobenius", func(t *testing.T) {
		var got, want Fp6
		p := FpOrder()
		for i := 0; i < testTimes; i++ {
			x := randomFp6(t)

			// Frob(x) == x^p
			got.Frob(x)
			expVarTime(&want, x, p)

			if got.IsEqual(&want) == 0 {
				test.ReportError(t, got, want, x)
			}
		}
	})
}

func BenchmarkFp6(b *testing.B) {
	x := randomFp6(b)
	y := randomFp6(b)
	z := randomFp6(b)
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
