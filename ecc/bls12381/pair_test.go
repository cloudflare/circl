package bls12381

import (
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381/ff"
)

func BenchmarkPair(b *testing.B) {
	g1 := G1Generator()
	g2 := G2Generator()
	f := miller(g1, g2)
	g := ff.EasyExponentiation(f)

	b.Run("Miller", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = miller(g1, g2)
		}
	})
	b.Run("EasyExp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ff.EasyExponentiation(f)
		}
	})
	b.Run("HardExp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			hardExponentiation(g)
		}
	})
	b.Run("FinalExp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = finalExp(f)
		}
	})
}
