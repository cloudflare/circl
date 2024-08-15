package slhdsa

import (
	"crypto/rand"
	"io"
	"testing"
)

func TestInner(t *testing.T) {
	for i := range supportedParams {
		param := &supportedParams[i]

		t.Run(param.name, func(t *testing.T) {
			t.Parallel()

			t.Run("Wots", func(t *testing.T) { testWotsPlus(t, param) })
			t.Run("Xmss", func(t *testing.T) { testXmss(t, param) })
			t.Run("Ht", func(tt *testing.T) { testHyperTree(tt, param) })
			t.Run("Fors", func(tt *testing.T) { testFors(tt, param) })
			t.Run("Int", func(tt *testing.T) { testInternal(tt, param) })
		})
	}
}

func BenchmarkInner(b *testing.B) {
	for i := range supportedParams {
		param := &supportedParams[i]

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
	_, err := io.ReadFull(rand.Reader, out)
	if err != nil {
		t.Fatalf("rand reader error: %v", err)
	}
	return
}
