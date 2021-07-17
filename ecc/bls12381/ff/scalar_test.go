package ff_test

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381/ff"
	"github.com/cloudflare/circl/internal/test"
)

func randomScalar(t testing.TB) *ff.Scalar {
	t.Helper()
	s := new(ff.Scalar)
	err := s.Random(rand.Reader)
	if err != nil {
		t.Error(err)
	}
	return s
}

func TestScalar(t *testing.T) {
	const testTimes = 1 << 10
	t.Run("set_bytes", func(t *testing.T) {
		for i := 0; i < testTimes; i++ {
			var y ff.Scalar
			x := randomScalar(t)
			bytes := x.Bytes()
			err := y.SetBytes(bytes)
			if err != nil {
				test.ReportError(t, x, y, x)
			}
			if !x.IsEqual(&y) {
				test.ReportError(t, x, y, x)
			}
		}
	})

	t.Run("no_alias", func(t *testing.T) {
		var want, got ff.Scalar
		x := randomScalar(t)
		got.Set(x)
		got.Sqr(&got)
		want.Set(x)
		want.Mul(&want, &want)
		if !got.IsEqual(&want) {
			test.ReportError(t, got, want, x)
		}
	})
	t.Run("mul_inv", func(t *testing.T) {
		var z ff.Scalar
		for i := 0; i < testTimes; i++ {
			x := randomScalar(t)
			y := randomScalar(t)
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
		var l0, l1, r0, r1 ff.Scalar
		for i := 0; i < testTimes; i++ {
			x := randomScalar(t)
			y := randomScalar(t)

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
}

func BenchmarkScalar(b *testing.B) {
	x := randomScalar(b)
	y := randomScalar(b)
	z := randomScalar(b)

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
