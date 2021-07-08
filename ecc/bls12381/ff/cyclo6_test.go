package ff

import (
	"math/big"
	"testing"

	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/internal/test"
)

func randomCyclo6() *Cyclo6 { return EasyExponentiation(randomFp12()) }

// phi6primeSq evaluates the 6-th cyclotomic polynomial, \phi_6(x) = x^2-x+1, at p^2.
func phi6primeSq() *big.Int {
	one := new(big.Int).SetUint64(1)
	p2 := new(big.Int).Mul(blsPrime, blsPrime) // p^2
	p := new(big.Int).Sub(p2, one)             // p^2 - 1
	p.Mul(p, p2)                               // p^4 - p^2
	p.Add(p, one)                              // p^4 - p^2 + 1
	return p
}

func TestCyclo6(t *testing.T) {
	const testTimes = 1 << 10
	t.Run("no_alias", func(t *testing.T) {
		var want, got Cyclo6
		x := randomCyclo6()
		got.Set(x)
		got.Sqr(&got)
		want.Set(x)
		want.Mul(&want, &want)
		if !got.IsEqual(&want) {
			test.ReportError(t, got, want, x)
		}
	})
	t.Run("order", func(t *testing.T) {
		cyclo6Order := phi6primeSq()
		l := (cyclo6Order.BitLen() + 7) >> 3
		cyclo6OrderBytes := make([]byte, l)
		conv.BigInt2BytesLe(cyclo6OrderBytes, cyclo6Order)

		var z12 Fp12
		for i := 0; i < 16; i++ {
			x := randomCyclo6()
			z12.Exp((*Fp12)(x), cyclo6OrderBytes)
			z := Cyclo6(z12)

			// x^phi6primeSq = 1
			got := z.IsIdentity()
			want := true
			if got != want {
				test.ReportError(t, got, want, x)
			}
		}
	})
	t.Run("mul_inv", func(t *testing.T) {
		var z Cyclo6
		for i := 0; i < testTimes; i++ {
			x := randomCyclo6()
			y := randomCyclo6()

			// x*y*x^1 = y
			z.Inv(x)
			z.Mul(&z, y)
			z.Mul(&z, x)
			got := z
			want := y
			if !got.IsEqual(want) {
				test.ReportError(t, got, want, x, y)
			}
		}
	})
	t.Run("mul_sqr", func(t *testing.T) {
		var want, got Cyclo6
		for i := 0; i < testTimes; i++ {
			x := randomCyclo6()

			// x*x = x^2
			got.Mul(x, x)
			want.Sqr(x)
			if !got.IsEqual(&want) {
				test.ReportError(t, got, want, x)
			}
		}
	})
}

func BenchmarkCyclo6(b *testing.B) {
	x := randomCyclo6()
	y := randomCyclo6()
	z := randomCyclo6()
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
