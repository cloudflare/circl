package goldilocks_test

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/ecc/goldilocks"
	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/internal/test"
)

func TestReduceModOrder(t *testing.T) {
	order := goldilocks.Curve{}.Order()
	bigOrder := conv.BytesLe2BigInt(order[:])
	const max = 3*goldilocks.ScalarSize - 1
	var b [max]byte
	_, _ = rand.Read(b[:])
	var z goldilocks.Scalar
	for i := 0; i < max; i++ {
		x := b[0:i]
		bigX := conv.BytesLe2BigInt(x)

		z.FromBytes(x)
		got := conv.BytesLe2BigInt(z[:])
		got.Mod(got, bigOrder)

		want := bigX.Mod(bigX, bigOrder)

		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, x, i)
		}
	}
}

func testOp(t *testing.T,
	f func(z, x, y *goldilocks.Scalar),
	g func(z, x, y *big.Int),
) {
	const testTimes = 1 << 8
	var x, y, z goldilocks.Scalar
	order := goldilocks.Curve{}.Order()
	want := new(big.Int)
	bigOrder := conv.BytesLe2BigInt(order[:])

	for i := 0; i < testTimes; i++ {
		_, _ = rand.Read(x[:])
		_, _ = rand.Read(y[:])
		bigX := conv.BytesLe2BigInt(x[:])
		bigY := conv.BytesLe2BigInt(y[:])

		f(&z, &x, &y)
		got := conv.BytesLe2BigInt(z[:])

		g(want, bigX, bigY)
		want.Mod(want, bigOrder)
		if got.Cmp(want) != 0 {
			test.ReportError(t, got.Text(16), want.Text(16),
				conv.BytesLe2Hex(x[:]),
				conv.BytesLe2Hex(y[:]))
		}
	}
}

func TestScalar(t *testing.T) {
	t.Run("Add", func(t *testing.T) {
		testOp(t,
			func(z, x, y *goldilocks.Scalar) { z.Add(x, y) },
			func(z, x, y *big.Int) { z.Add(x, y) })
	})
	t.Run("Sub", func(t *testing.T) {
		testOp(t,
			func(z, x, y *goldilocks.Scalar) { z.Sub(x, y) },
			func(z, x, y *big.Int) { z.Sub(x, y) })
	})
	t.Run("Mul", func(t *testing.T) {
		testOp(t,
			func(z, x, y *goldilocks.Scalar) { z.Mul(x, y) },
			func(z, x, y *big.Int) { z.Mul(x, y) })
	})
}

func BenchmarkScalar(b *testing.B) {
	var k [2 * goldilocks.ScalarSize]byte
	var x, y, z goldilocks.Scalar
	_ = binary.Read(rand.Reader, binary.LittleEndian, x[:])
	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Add(&x, &y)
		}
	})
	b.Run("Sub", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Sub(&x, &y)
		}
	})
	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Mul(&x, &y)
		}
	})
	b.Run("Red", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.FromBytes(k[:])
		}
	})
}
