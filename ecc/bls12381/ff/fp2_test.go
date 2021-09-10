package ff

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func randomFp2(t testing.TB) *Fp2 { return &Fp2{*randomFp(t), *randomFp(t)} }

func TestFp2(t *testing.T) {
	const testTimes = 1 << 9
	t.Run("no_alias", func(t *testing.T) {
		var want, got Fp2
		x := randomFp2(t)
		got = *x
		got.Sqr(&got)
		want = *x
		want.Mul(&want, &want)
		if got.IsEqual(&want) == 0 {
			test.ReportError(t, got, want, x)
		}
	})
	t.Run("mul_inv", func(t *testing.T) {
		var z Fp2
		for i := 0; i < testTimes; i++ {
			x := randomFp2(t)
			y := randomFp2(t)

			// x*y*x^1 - y = 0
			z.Inv(x)
			z.Mul(&z, y)
			z.Mul(&z, x)
			z.Sub(&z, y)
			got := z.IsZero()
			want := 1
			if got != want {
				test.ReportError(t, got, want, x, y, z)
			}
		}
	})
	t.Run("mul_sqr", func(t *testing.T) {
		var l0, l1, r0, r1 Fp2
		for i := 0; i < testTimes; i++ {
			x := randomFp2(t)
			y := randomFp2(t)

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
	t.Run("sqrt", func(t *testing.T) {
		var r, notRoot, got Fp2
		// Check when x has square-root.
		for i := 0; i < testTimes; i++ {
			x := randomFp2(t)
			x.Sqr(x)

			// let x is QR and r = sqrt(x); check (+r)^2 = (-r)^2 = x.
			isQR := r.Sqrt(x)
			test.CheckOk(isQR == 1, fmt.Sprintf("should be a QR: %v", x), t)
			rNeg := r
			rNeg.Neg()

			want := x
			for _, root := range []*Fp2{&r, &rNeg} {
				got.Sqr(root)
				if got.IsEqual(want) == 0 {
					test.ReportError(t, got, want, x, root)
				}
			}
		}
		// Check when x has not square-root.
		var uPlus1 Fp2
		uPlus1[0].SetUint64(1)
		uPlus1[1].SetUint64(1)
		for i := 0; i < testTimes; i++ {
			want := randomFp2(t)
			x := randomFp2(t)
			x.Sqr(x)
			x.Mul(x, &uPlus1) // x = (u+1)*(x^2), since u+1 is not QR in Fp2.

			// let x is not QR and r = sqrt(x); check that r was not modified.
			got := want
			isQR := got.Sqrt(x)
			test.CheckOk(isQR == 0, fmt.Sprintf("shouldn't be a QR: %v", x), t)

			if got.IsEqual(want) != 1 {
				test.ReportError(t, got, want, x, notRoot)
			}
		}
	})
	t.Run("marshal", func(t *testing.T) {
		var b Fp2
		for i := 0; i < testTimes; i++ {
			a := randomFp2(t)
			s, err := a.MarshalBinary()
			test.CheckNoErr(t, err, "MarshalBinary failed")
			err = b.UnmarshalBinary(s)
			test.CheckNoErr(t, err, "UnmarshalBinary failed")
			if b.IsEqual(a) == 0 {
				test.ReportError(t, a, b)
			}
		}
	})
}

func BenchmarkFp2(b *testing.B) {
	x := randomFp2(b)
	y := randomFp2(b)
	z := randomFp2(b)
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
