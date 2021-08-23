package bls12381

import (
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func randomG2(t testing.TB) *G2 {
	var P G2
	k := randomScalar(t)
	P.ScalarMult(k, G2Generator())
	if !P.IsOnCurve() {
		t.Helper()
		t.Fatal("not on curve")
	}
	return &P
}

func TestG2Add(t *testing.T) {
	const testTimes = 1 << 6
	var Q, R G2
	for i := 0; i < testTimes; i++ {
		P := randomG2(t)
		Q.Set(P)
		R.Set(P)
		R.Add(&R, &R)
		R.Neg()
		Q.Double()
		Q.Neg()
		got := R
		want := Q
		if !got.IsEqual(&want) {
			test.ReportError(t, got, want, P)
		}
	}
}

func TestG2ScalarMult(t *testing.T) {
	const testTimes = 1 << 6
	var Q G2
	for i := 0; i < testTimes; i++ {
		P := randomG2(t)
		k := randomScalar(t)
		Q.ScalarMult(k, P)
		Q.Normalize()
		got := Q.IsOnG2()
		want := true
		if got != want {
			test.ReportError(t, got, want, P)
		}
	}
}

func TestG2Serial(t *testing.T) {
	testTimes := 1 << 6
	for i := 0; i < testTimes; i++ {
		P := randomG2(t)
		var Q G2
		b := P.Bytes()
		err := Q.SetBytes(b)
		if err != nil {
			t.Fatal("failure to deserialize")
		}
		if !Q.IsEqual(P) {
			t.Fatal("deserialization wrong point")
		}
	}
}

func BenchmarkG2(b *testing.B) {
	P := randomG2(b)
	Q := randomG2(b)
	k := randomScalar(b)

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.Add(P, Q)
		}
	})
	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.ScalarMult(k, P)
		}
	})
}

func TestGTorsion(t *testing.T) {
	if !G2Generator().IsRTorsion() {
		t.Fatalf("Generator is not torsion")
	}
}
