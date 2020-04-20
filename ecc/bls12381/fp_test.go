package bls12381

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func randomFp() *fp {
	var x fp
	n, _ := rand.Int(rand.Reader, blsPrime)
	x.Int.Set(n)
	return &x
}

func TestFp(t *testing.T) {
	const testTimes = 1 << 6
	var z fp
	for i := 0; i < testTimes; i++ {
		x := randomFp()
		y := randomFp()

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
}
func BenchmarkFp(b *testing.B) {
	x := randomFp()
	y := randomFp()
	z := randomFp()
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
