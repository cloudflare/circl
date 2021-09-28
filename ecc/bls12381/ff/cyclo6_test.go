package ff

import (
	"math/big"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func randomCyclo6(t testing.TB) *Cyclo6 {
	c := &Cyclo6{}
	EasyExponentiation(c, randomFp12(t))
	return c
}

// phi6primeSq evaluates the 6-th cyclotomic polynomial, \phi_6(x) = x^2-x+1, at p^2.
func phi6primeSq() []byte {
	one := big.NewInt(1)
	p := new(big.Int).SetBytes(fpOrder[:]) // p
	p2 := new(big.Int).Mul(p, p)           // p^2
	p4 := new(big.Int).Sub(p2, one)        // p^2 - 1
	p4.Mul(p4, p2)                         // p^4 - p^2
	p4.Add(p4, one)                        // p^4 - p^2 + 1
	return p4.Bytes()
}

func TestCyclo6(t *testing.T) {
	const testTimes = 1 << 10
	t.Run("no_alias", func(t *testing.T) {
		var want, got Cyclo6
		x := randomCyclo6(t)
		got = *x
		got.Sqr(&got)
		want = *x
		want.Mul(&want, &want)
		if got.IsEqual(&want) == 0 {
			test.ReportError(t, got, want, x)
		}
	})
	t.Run("order", func(t *testing.T) {
		cyclo6Order := phi6primeSq()
		var z Cyclo6
		for i := 0; i < 16; i++ {
			x := randomCyclo6(t)
			z.exp(x, cyclo6Order)

			// x^phi6primeSq = 1
			got := z.IsIdentity()
			want := 1
			if got != want {
				test.ReportError(t, got, want, x, z)
			}
		}
	})
	t.Run("mul_inv", func(t *testing.T) {
		var z Cyclo6
		for i := 0; i < testTimes; i++ {
			x := randomCyclo6(t)
			y := randomCyclo6(t)

			// x*y*x^1 = y
			z.Inv(x)
			z.Mul(&z, y)
			z.Mul(&z, x)
			got := z
			want := y
			if got.IsEqual(want) == 0 {
				test.ReportError(t, got, want, x, y)
			}
		}
	})
	t.Run("mul_sqr", func(t *testing.T) {
		var want, got Cyclo6
		for i := 0; i < testTimes; i++ {
			x := randomCyclo6(t)

			// x*x = x^2
			got.Mul(x, x)
			want.Sqr(x)
			if got.IsEqual(&want) == 0 {
				test.ReportError(t, got, want, x)
			}
		}
	})

	t.Run("invFp12_vs_invCyclo6", func(t *testing.T) {
		var want, got Fp12
		var y Cyclo6
		for i := 0; i < testTimes; i++ {
			x := randomCyclo6(t)

			y.Inv(x)
			got = (Fp12)(y)
			want.Inv((*Fp12)(x))

			if got.IsEqual(&want) == 0 {
				test.ReportError(t, got, want, x)
			}
		}
	})
}

func BenchmarkCyclo6(b *testing.B) {
	x := randomCyclo6(b)
	y := randomCyclo6(b)
	z := randomCyclo6(b)
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
	b.Run("PowToX", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.PowToX(x)
		}
	})
}
