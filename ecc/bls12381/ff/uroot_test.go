package ff

import (
	"math/big"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func randomURoot(t testing.TB) *URoot {
	u := &URoot{}
	HardExponentiation(u, randomCyclo6(t))
	return u
}

func TestURoot(t *testing.T) {
	const testTimes = 1 << 8
	t.Run("no_alias", func(t *testing.T) {
		var want, got URoot
		x := randomURoot(t)
		got = *x
		got.Sqr(&got)
		want = *x
		want.Mul(&want, &want)
		if got.IsEqual(&want) == 0 {
			test.ReportError(t, got, want, x)
		}
	})
	t.Run("order", func(t *testing.T) {
		order := ScalarOrder()

		var z URoot
		for i := 0; i < 16; i++ {
			x := randomURoot(t)
			(*Cyclo6)(&z).exp((*Cyclo6)(x), order)

			// x^order = 1
			got := z.IsIdentity()
			want := 1
			if got != want {
				test.ReportError(t, got, want, x, z)
			}
		}
	})
	t.Run("mul_inv", func(t *testing.T) {
		var z URoot
		for i := 0; i < testTimes; i++ {
			x := randomURoot(t)
			y := randomURoot(t)

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
		var want, got URoot
		for i := 0; i < testTimes; i++ {
			x := randomURoot(t)

			// x*x = x^2
			got.Mul(x, x)
			want.Sqr(x)
			if got.IsEqual(&want) == 0 {
				test.ReportError(t, got, want, x)
			}
		}
	})
	t.Run("unmarshal", func(t *testing.T) {
		valid := []*URoot{{}}
		valid[0].SetIdentity()
		for i := 0; i < 16; i++ {
			valid = append(valid, randomURoot(t))
		}
		for _, x := range valid {
			b, err := x.MarshalBinary()
			test.CheckNoErr(t, err, "marshal failed")
			var got URoot
			test.CheckNoErr(t, got.UnmarshalBinary(b), "should accept an n-th root of unity")
			if got.IsEqual(x) == 0 {
				test.ReportError(t, got, x)
			}
		}

		// Zero, elements not in Cyclo6, and elements of Cyclo6 whose order
		// does not divide n.
		two := &Fp12{}
		two[0][0][0].SetUint64(2)
		invalid := []*Fp12{{}, two}
		for i := 0; i < 16; i++ {
			invalid = append(invalid, randomFp12(t), (*Fp12)(randomCyclo6(t)))
		}
		for _, x := range invalid {
			b, err := x.MarshalBinary()
			test.CheckNoErr(t, err, "marshal failed")
			var got URoot
			test.CheckIsErr(t, got.UnmarshalBinary(b), "should reject a non n-th root of unity")
		}
	})
	t.Run("subgroup_check", func(t *testing.T) {
		// isValid relies on gcd(p-paramX, Φ12(p)) = n.
		p := new(big.Int).SetBytes(fpOrder[:])
		paramX, _ := new(big.Int).SetString("-0xd201000000010000", 0)
		phi := new(big.Int).SetBytes(phi6primeSq())
		got := new(big.Int).GCD(nil, nil, p.Sub(p, paramX), phi)
		want := new(big.Int).SetBytes(ScalarOrder())
		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want)
		}
	})
}

func BenchmarkURoot(b *testing.B) {
	x := randomURoot(b)
	y := randomURoot(b)
	z := randomURoot(b)
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
