package bls12381

import (
	"crypto/rand"
	"testing"
)

func BenchmarkGt(b *testing.B) {
	sc := &Scalar{}
	err := sc.Random(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	g1 := G1Generator()
	g2 := G2Generator()
	e1 := Pair(g1, g2)

	g1.ScalarMult(sc, g1)
	e2 := Pair(g1, g2)
	e3 := &Gt{}

	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			e3.Mul(e1, e2)
		}
	})
	b.Run("Exp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			e3.Exp(e1, sc)
		}
	})
}
