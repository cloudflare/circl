package slhdsa

import (
	"crypto/rand"
	"flag"
	"testing"
)

// RunLongTest indicates whether long tests should be run.
var RunLongTest = flag.Bool("long", false, "runs longer tests and benchmark")

func SkipLongTest(t testing.TB) {
	t.Helper()
	if !*RunLongTest {
		t.Skip("Skipped one long test, add -long flag to run longer tests")
	}
}

func InnerTest(t *testing.T, sigIDs []ID) {
	SkipLongTest(t)
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

func BenchInner(b *testing.B, sigIDs []ID) {
	SkipLongTest(b)
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
