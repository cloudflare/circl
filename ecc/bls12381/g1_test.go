package bls12381

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func randomG1() *G1 {
	return G1Generator()
}

func TestG1ScalarMult(t *testing.T) {
	const testTimes = 1 << 6
	var k Scalar
	var Q G1
	for i := 0; i < testTimes; i++ {
		_, _ = rand.Read(k[:])
		P := randomG1()
		Q.ScalarMult(&k, P)
		got := Q
		want := Q
		if got.IsEqual(&want) {
			test.ReportError(t, got, want, k)
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
