package bls12381

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381/ff"
)

func BenchmarkMiller(b *testing.B) {
	g1 := G1Generator()
	g2 := G2Generator()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = miller(g1, g2)
	}
}

func BenchmarkFinalExpo(b *testing.B) {
	g1 := G1Generator()
	g2 := G2Generator()
	f := miller(g1, g2)
	g := ff.EasyExponentiation(f)

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

func BenchmarkPair(b *testing.B) {
	g1 := G1Generator()
	g2 := G2Generator()

	const N = 3
	listG1 := [N]*G1{}
	listG2 := [N]*G2{}
	listExp := [N]*Scalar{}
	for i := 0; i < N; i++ {
		listG1[i] = new(G1)
		listG1[i].Set(g1)
		listG2[i] = new(G2)
		listG2[i].Set(g2)
		listExp[i] = &Scalar{}
		listExp[i].Random()
	}

	b.Run("Pair1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Pair(g1, g2)
		}
	})
	b.Run(fmt.Sprintf("Pair%v", N), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ProdPair(listG1[:], listG2[:], listExp[:])
		}
	})
}
