package ted448_test

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/ted448"
	"github.com/cloudflare/circl/internal/test"
)

func randomPoint() ted448.Point {
	var k ted448.Scalar
	_, _ = rand.Read(k[:])
	var P ted448.Point
	ted448.ScalarBaseMult(&P, &k)
	return P
}

func TestPointAdd(t *testing.T) {
	const testTimes = 1 << 10
	for i := 0; i < testTimes; i++ {
		P := randomPoint()
		Q := P
		// Q = 16P = 2^4P
		Q.Double() // 2P
		Q.Double() // 4P
		Q.Double() // 8P
		Q.Double() // 16P
		got := Q
		// R = 16P = P+P...+P
		R := ted448.Identity()
		for j := 0; j < 16; j++ {
			R.Add(&P)
		}
		want := R
		if !ted448.IsOnCurve(&got) || !ted448.IsOnCurve(&want) || !got.IsEqual(&want) {
			test.ReportError(t, got, want, P)
		}
	}
}

func TestPointNeg(t *testing.T) {
	const testTimes = 1 << 10
	for i := 0; i < testTimes; i++ {
		P := randomPoint()
		Q := P
		Q.Neg()
		Q.Add(&P)
		got := Q.IsIdentity()
		want := true
		if got != want {
			test.ReportError(t, got, want, P)
		}
	}
}

func TestScalarMult(t *testing.T) {
	const testTimes = 1 << 8

	t.Run("rG=0", func(t *testing.T) {
		got := &ted448.Point{}
		order := ted448.Order()
		for i := 0; i < testTimes; i++ {
			ted448.ScalarBaseMult(got, &order)
			want := ted448.Identity()

			if !ted448.IsOnCurve(got) || !ted448.IsOnCurve(&want) || !got.IsEqual(&want) {
				test.ReportError(t, got, want)
			}
		}
	})
	t.Run("rP=0", func(t *testing.T) {
		got := &ted448.Point{}
		order := ted448.Order()
		for i := 0; i < testTimes; i++ {
			P := randomPoint()

			ted448.ScalarMult(got, &order, &P)
			want := ted448.Identity()

			if !ted448.IsOnCurve(got) || !ted448.IsOnCurve(&want) || !got.IsEqual(&want) {
				test.ReportError(t, got, want, P, order)
			}
		}
	})
	t.Run("kG", func(t *testing.T) {
		k := &ted448.Scalar{}
		zero := &ted448.Scalar{}
		got := &ted448.Point{}
		want := &ted448.Point{}
		I := ted448.Identity()
		for i := 0; i < testTimes; i++ {
			_, _ = rand.Read(k[:])

			ted448.ScalarBaseMult(got, k)
			ted448.CombinedMult(want, k, zero, &I) // k*G + 0*I

			if !ted448.IsOnCurve(got) || !ted448.IsOnCurve(want) || !got.IsEqual(want) {
				test.ReportError(t, got, want, k)
			}
		}
	})
	t.Run("kP", func(t *testing.T) {
		k := &ted448.Scalar{}
		zero := &ted448.Scalar{}
		got := &ted448.Point{}
		want := &ted448.Point{}
		for i := 0; i < testTimes; i++ {
			P := randomPoint()
			_, _ = rand.Read(k[:])

			ted448.ScalarMult(got, k, &P)
			ted448.CombinedMult(want, zero, k, &P)

			if !ted448.IsOnCurve(got) || !ted448.IsOnCurve(want) || !got.IsEqual(want) {
				test.ReportError(t, got, want, P, k)
			}
		}
	})
	t.Run("kG+lP", func(t *testing.T) {
		want := &ted448.Point{}
		kG := &ted448.Point{}
		lP := &ted448.Point{}
		G := ted448.Generator()
		k := &ted448.Scalar{}
		l := &ted448.Scalar{}
		for i := 0; i < testTimes; i++ {
			P := randomPoint()
			_, _ = rand.Read(k[:])
			_, _ = rand.Read(l[:])

			ted448.ScalarMult(kG, k, &G)
			ted448.ScalarMult(lP, l, &P)
			kG.Add(lP)
			got := kG
			ted448.CombinedMult(want, k, l, &P)

			if !ted448.IsOnCurve(got) || !ted448.IsOnCurve(want) || !got.IsEqual(want) {
				test.ReportError(t, got, want, P, k, l)
			}
		}
	})
}

func BenchmarkCurve(b *testing.B) {
	var k, l ted448.Scalar
	_, _ = rand.Read(k[:])
	_, _ = rand.Read(l[:])
	P := randomPoint()
	Q := randomPoint()

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.Add(&Q)
		}
	})
	b.Run("ScalarMult", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ted448.ScalarMult(&P, &k, &P)
		}
	})
	b.Run("ScalarBaseMult", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ted448.ScalarBaseMult(&P, &k)
		}
	})
	b.Run("CombinedMult", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ted448.CombinedMult(&P, &k, &l, &P)
		}
	})
}
