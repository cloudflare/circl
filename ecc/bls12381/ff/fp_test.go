package ff

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func randomFp(t testing.TB) *Fp {
	t.Helper()
	f := new(Fp)
	err := f.Random(rand.Reader)
	if err != nil {
		t.Error(err)
	}
	return f
}

func TestFp(t *testing.T) {
	const testTimes = 1 << 10
	t.Run("no_alias", func(t *testing.T) {
		var want, got Fp
		x := randomFp(t)
		got.Set(x)
		got.Sqr(&got)
		want.Set(x)
		want.Mul(&want, &want)
		if got.IsEqual(&want) == 0 {
			test.ReportError(t, got, want, x)
		}
	})
	t.Run("mul_inv", func(t *testing.T) {
		var z Fp
		for i := 0; i < testTimes; i++ {
			x := randomFp(t)
			y := randomFp(t)

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
		var l0, l1, r0, r1 Fp
		for i := 0; i < testTimes; i++ {
			x := randomFp(t)
			y := randomFp(t)

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
	t.Run("serdes", func(t *testing.T) {
		var b Fp
		for i := 0; i < testTimes; i++ {
			a := randomFp(t)
			s := a.Bytes()
			err := b.SetBytes(s)
			test.CheckNoErr(t, err, "setbytes failed")
			if b.IsEqual(a) == 0 {
				test.ReportError(t, a, b)
			}
		}
	})
}

func BenchmarkFp(b *testing.B) {
	x := randomFp(b)
	y := randomFp(b)
	z := randomFp(b)
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
