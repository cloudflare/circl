package slhdsa

import (
	"crypto/rand"
	"testing"
)

func InnerTest(t *testing.T, sigIDs []ID) {
	for _, id := range sigIDs {
		param := id.params()
		t.Run(id.String(), func(t *testing.T) {
			t.Run("Wots", func(t *testing.T) { testWotsPlus(t, param) })
			t.Run("Xmss", func(t *testing.T) { testXmss(t, param) })
			t.Run("Ht", func(tt *testing.T) { testHyperTree(t, param) })
			t.Run("Fors", func(tt *testing.T) { testFors(t, param) })
			t.Run("Int", func(tt *testing.T) { testInternal(t, param) })
		})
	}
}

func InnerBenchmark(b *testing.B, sigIDs []ID) {
	for _, id := range sigIDs {
		param := id.params()
		b.Run(param.name, func(b *testing.B) {
			b.Run("Wots", func(b *testing.B) { benchmarkWotsPlus(b, param) })
			b.Run("Xmss", func(b *testing.B) { benchmarkXmss(b, param) })
			b.Run("Ht", func(b *testing.B) { benchmarkHyperTree(b, param) })
			b.Run("Fors", func(b *testing.B) { benchmarkFors(b, param) })
			b.Run("Int", func(b *testing.B) { benchmarkInternal(b, param) })
		})
	}
}

func mustRead(t testing.TB, size uint32) (out []byte) {
	out = make([]byte, size)
	_, err := rand.Read(out)
	if err != nil {
		t.Fatalf("rand reader error: %v", err)
	}
	return
}
