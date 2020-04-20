package bls12381

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func randomG1() *G1 {
	var P G1
	var k Scalar
	_, _ = rand.Read(k[:])
	P.ScalarMult(&k, G1Generator())
	if !P.IsOnCurve() {
		panic("not on curve")
	}
	return &P
}

func TestG1Add(t *testing.T) {
	const testTimes = 1 << 6
	for i := 0; i < testTimes; i++ {
		P := randomG1()
		Q := *P
		P.Add(P, P)
		P.Neg()
		Q.Double()
		Q.Neg()
		got := P
		want := Q
		if !got.IsEqual(&want) {
			test.ReportError(t, got, want, P)
		}
	}
}

func TestG1ScalarMult(t *testing.T) {
	const testTimes = 1 << 6
	var k Scalar
	var Q G1
	for i := 0; i < testTimes; i++ {
		P := randomG1()
		_, _ = rand.Read(k[:])
		Q.ScalarMult(&k, P)
		Q.ToAffine()
		got := Q.IsOnG1()
		want := true
		if got != want {
			test.ReportError(t, got, want, P)
		}
	}
}

func BenchmarkG1ScalarMult(b *testing.B) {
	var k Scalar
	var P G1
	_, _ = rand.Read(k[:])
	for i := 0; i < b.N; i++ {
		P.ScalarMult(&k, &P)
	}
}
