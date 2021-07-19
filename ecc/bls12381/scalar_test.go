package bls12381

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func TestScalar(t *testing.T) {
	const testTimes = 1 << 10
	t.Run("set_bytes", func(t *testing.T) {
		for i := 0; i < testTimes; i++ {
			var x, y Scalar
			err := x.Random(rand.Reader)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			bytes := x.Bytes()
			err = y.SetBytes(bytes)
			if err != nil {
				test.ReportError(t, x, y, x)
			}
			if !x.IsEqual(&y) {
				test.ReportError(t, x, y, x)
			}
		}
	})

	t.Run("no_alias", func(t *testing.T) {
		var want, got Scalar
		var x Scalar
		err := x.Random(rand.Reader)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		got.Set(&x)
		got.Sqr(&got)
		want.Set(&x)
		want.Mul(&want, &want)
		if !got.IsEqual(&want) {
			test.ReportError(t, got, want, x)
		}
	})
	t.Run("mul_inv", func(t *testing.T) {
		var x, y, z Scalar
		for i := 0; i < testTimes; i++ {
			err := x.Random(rand.Reader)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			err = y.Random(rand.Reader)
			if err != nil {
				t.Fatalf("error: %v", err)
			}

			// x*y*x^1 - y = 0
			z.Inv(&x)
			z.Mul(&z, &y)
			z.Mul(&z, &x)
			z.Sub(&z, &y)
			got := z.IsZero()
			want := true
			if got != want {
				test.ReportError(t, got, want, x, y)
			}
		}
	})
	t.Run("mul_sqr", func(t *testing.T) {
		var x, y, l0, l1, r0, r1 Scalar
		for i := 0; i < testTimes; i++ {
			err := x.Random(rand.Reader)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			err = y.Random(rand.Reader)
			if err != nil {
				t.Fatalf("error: %v", err)
			}

			// (x+y)(x-y) = (x^2-y^2)
			l0.Add(&x, &y)
			l1.Sub(&x, &y)
			l0.Mul(&l0, &l1)
			r0.Sqr(&x)
			r1.Sqr(&y)
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
	var x, y, z Scalar
	err := x.Random(rand.Reader)
	if err != nil {
		b.Fatalf("error: %v", err)
	}
	err = y.Random(rand.Reader)
	if err != nil {
		b.Fatalf("error: %v", err)
	}
	err = z.Random(rand.Reader)
	if err != nil {
		b.Fatalf("error: %v", err)
	}
	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Add(&x, &y)
		}
	})
	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Mul(&x, &y)
		}
	})
	b.Run("Sqr", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Sqr(&x)
		}
	})
	b.Run("Inv", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Inv(&x)
		}
	})
}
