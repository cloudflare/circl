package bls12381

import (
	"fmt"
	"testing"
)

func TestDevel(t *testing.T) {
	t.Logf("Devel\n")

	g1 := G1Generator()
	g2 := G2Generator()
	g3 := miller(g1, g2)

	fmt.Printf("g1:\n%v\n", g1)
	fmt.Printf("g2:\n%v\n", g2)
	fmt.Printf("g3:\n%v\n", g3)
}

func BenchmarkPair(b *testing.B) {
	var P G1
	var Q G2
	b.Run("Miller", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			miller(&P, &Q)
		}
	})
}
