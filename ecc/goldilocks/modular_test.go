package goldilocks

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/internal/test"
)

func TestReduceModOrder(t *testing.T) {
	bigOrder := conv.BytesLe2BigInt(order[:])
	const max = 2*ScalarSize - 1
	var b [max]byte
	var z [ScalarSize]byte
	for i := 0; i < max; i++ {
		x := b[0:i]
		binary.Read(rand.Reader, binary.LittleEndian, x)
		bigX := conv.BytesLe2BigInt(x)

		reduceModOrder(z[:], x)
		got := conv.BytesLe2BigInt(x)
		got.Mod(got, bigOrder)

		want := bigX.Mod(bigX, bigOrder)

		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want)
		}
	}
}

func BenchmarkReduceModOrder(b *testing.B) {
	var x [2 * ScalarSize]byte
	var z [ScalarSize]byte
	binary.Read(rand.Reader, binary.LittleEndian, x[:])
	for i := 0; i < b.N; i++ {
		reduceModOrder(z[:], x[:])
	}
}
