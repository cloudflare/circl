package goldilocks_test

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/ecc/goldilocks"
)

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
