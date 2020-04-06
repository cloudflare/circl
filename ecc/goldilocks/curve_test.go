package goldilocks_test

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/ecc/goldilocks"
	"github.com/cloudflare/circl/internal/test"
)

func TestScalarMult(t *testing.T) {
	const testTimes = 1 << 8
	var e goldilocks.Curve
	k := &goldilocks.Scalar{}
	zero := &goldilocks.Scalar{}

	t.Run("rG=0", func(t *testing.T) {
		order := e.Order()
		for i := 0; i < testTimes; i++ {
			got := e.ScalarBaseMult(&order)
			got.ToAffine()
			want := e.Identity()

			if !e.IsOnCurve(got) || !e.IsOnCurve(want) || !got.IsEqual(want) {
				want.ToAffine()
				test.ReportError(t, got, want)
			}
		}
	})
	t.Run("rP=0", func(t *testing.T) {
		order := e.Order()
		for i := 0; i < testTimes; i++ {
			P := randomPoint()

			got := e.ScalarMult(&order, P)
			got.ToAffine()
			want := e.Identity()

			if !e.IsOnCurve(got) || !e.IsOnCurve(want) || !got.IsEqual(want) {
				want.ToAffine()
				test.ReportError(t, got, want, P, order)
			}
		}
	})
	t.Run("kG", func(t *testing.T) {
		I := e.Identity()
		for i := 0; i < testTimes; i++ {
			_, _ = rand.Read(k[:])

			got := e.ScalarBaseMult(k)
			want := e.CombinedMult(k, zero, I) // k*G + 0*I

			if !e.IsOnCurve(got) || !e.IsOnCurve(want) || !got.IsEqual(want) {
				test.ReportError(t, got, want, k)
			}
		}
	})
	t.Run("kP", func(t *testing.T) {
		for i := 0; i < testTimes; i++ {
			P := randomPoint()
			_, _ = rand.Read(k[:])

			got := e.ScalarMult(k, P)
			want := e.CombinedMult(zero, k, P)

			if !e.IsOnCurve(got) || !e.IsOnCurve(want) || !got.IsEqual(want) {
				test.ReportError(t, got, want, P, k)
			}
		}
	})
	t.Run("kG+lP", func(t *testing.T) {
		G := e.Generator()
		l := &goldilocks.Scalar{}
		for i := 0; i < testTimes; i++ {
			P := randomPoint()
			_, _ = rand.Read(k[:])
			_, _ = rand.Read(l[:])

			kG := e.ScalarMult(k, G)
			lP := e.ScalarMult(l, P)
			got := e.Add(kG, lP)
			want := e.CombinedMult(k, l, P)

			if !e.IsOnCurve(got) || !e.IsOnCurve(want) || !got.IsEqual(want) {
				test.ReportError(t, got, want, P, k, l)
			}
		}
	})
}

func BenchmarkCurve(b *testing.B) {
	var e goldilocks.Curve
	var k, l goldilocks.Scalar
	_, _ = rand.Read(k[:])
	_, _ = rand.Read(l[:])
	P := randomPoint()

	b.Run("ScalarMult", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P = e.ScalarMult(&k, P)
		}
	})
	b.Run("ScalarBaseMult", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			e.ScalarBaseMult(&k)
		}
	})
	b.Run("CombinedMult", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P = e.CombinedMult(&k, &l, P)
		}
	})
}
