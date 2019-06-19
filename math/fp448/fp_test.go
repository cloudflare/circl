package fp448

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/internal/test"
)

func testCmov(t *testing.T, f func(x, y *Elt, n uint)) {
	const numTests = 1 << 9
	var x, y Elt
	for i := 0; i < numTests; i++ {
		_, _ = rand.Read(x[:])
		_, _ = rand.Read(y[:])
		b := uint(y[0] & 0x1)
		want := conv.BytesLe2BigInt(x[:])
		if b != 0 {
			want = conv.BytesLe2BigInt(y[:])
		}

		f(&x, &y, b)
		got := conv.BytesLe2BigInt(x[:])

		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, x, y, b)
		}
	}
}

func testCswap(t *testing.T, f func(x, y *Elt, n uint)) {
	const numTests = 1 << 9
	var x, y Elt
	for i := 0; i < numTests; i++ {
		_, _ = rand.Read(x[:])
		_, _ = rand.Read(y[:])
		b := uint(y[0] & 0x1)
		want0 := conv.BytesLe2BigInt(x[:])
		want1 := conv.BytesLe2BigInt(y[:])
		if b != 0 {
			want0 = conv.BytesLe2BigInt(y[:])
			want1 = conv.BytesLe2BigInt(x[:])
		}

		f(&x, &y, b)
		got0 := conv.BytesLe2BigInt(x[:])
		got1 := conv.BytesLe2BigInt(y[:])

		if got0.Cmp(want0) != 0 {
			test.ReportError(t, got0, want0, x, y, b)
		}
		if got1.Cmp(want1) != 0 {
			test.ReportError(t, got1, want1, x, y, b)
		}
	}
}

func testAdd(t *testing.T, f func(z, x, y *Elt)) {
	const numTests = 1 << 9
	var x, y, z Elt
	prime := P()
	p := conv.BytesLe2BigInt(prime[:])
	for i := 0; i < numTests; i++ {
		_, _ = rand.Read(x[:])
		_, _ = rand.Read(y[:])
		f(&z, &x, &y)
		Modp(&z)
		got := conv.BytesLe2BigInt(z[:])

		xx, yy := conv.BytesLe2BigInt(x[:]), conv.BytesLe2BigInt(y[:])
		want := xx.Add(xx, yy).Mod(xx, p)

		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, x, y)
		}
	}
}

func testSub(t *testing.T, f func(z, x, y *Elt)) {
	const numTests = 1 << 9
	var x, y, z Elt
	prime := P()
	p := conv.BytesLe2BigInt(prime[:])
	for i := 0; i < numTests; i++ {
		_, _ = rand.Read(x[:])
		_, _ = rand.Read(y[:])
		f(&z, &x, &y)
		Modp(&z)
		got := conv.BytesLe2BigInt(z[:])

		xx, yy := conv.BytesLe2BigInt(x[:]), conv.BytesLe2BigInt(y[:])
		want := xx.Sub(xx, yy).Mod(xx, p)

		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, x, y)
		}
	}
}

func testAddSub(t *testing.T, f func(x, y *Elt)) {
	const numTests = 1 << 9
	var x, y Elt
	prime := P()
	p := conv.BytesLe2BigInt(prime[:])
	want0, want1 := big.NewInt(0), big.NewInt(0)
	for i := 0; i < numTests; i++ {
		_, _ = rand.Read(x[:])
		_, _ = rand.Read(y[:])
		xx, yy := conv.BytesLe2BigInt(x[:]), conv.BytesLe2BigInt(y[:])
		want0.Add(xx, yy).Mod(want0, p)
		want1.Sub(xx, yy).Mod(want1, p)

		f(&x, &y)
		Modp(&x)
		Modp(&y)
		got0 := conv.BytesLe2BigInt(x[:])
		got1 := conv.BytesLe2BigInt(y[:])

		if got0.Cmp(want0) != 0 {
			test.ReportError(t, got0, want0, x, y)
		}
		if got1.Cmp(want1) != 0 {
			test.ReportError(t, got1, want1, x, y)
		}
	}
}

func testMul(t *testing.T, f func(z, x, y *Elt)) {
	const numTests = 1 << 9
	var x, y, z Elt
	prime := P()
	p := conv.BytesLe2BigInt(prime[:])
	for i := 0; i < numTests; i++ {
		_, _ = rand.Read(x[:])
		_, _ = rand.Read(y[:])
		f(&z, &x, &y)
		Modp(&z)
		got := conv.BytesLe2BigInt(z[:])

		xx, yy := conv.BytesLe2BigInt(x[:]), conv.BytesLe2BigInt(y[:])
		want := xx.Mul(xx, yy).Mod(xx, p)

		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, x, y)
		}
	}
}

func testSqr(t *testing.T, f func(z, x *Elt)) {
	const numTests = 1 << 9
	var x, z Elt
	prime := P()
	p := conv.BytesLe2BigInt(prime[:])
	for i := 0; i < numTests; i++ {
		_, _ = rand.Read(x[:])
		f(&z, &x)
		Modp(&z)
		got := conv.BytesLe2BigInt(z[:])

		xx := conv.BytesLe2BigInt(x[:])
		want := xx.Mul(xx, xx).Mod(xx, p)

		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, x)
		}
	}
}

func TestModp(t *testing.T) {
	const numTests = 1 << 9
	var x Elt
	prime := P()
	p := conv.BytesLe2BigInt(prime[:])
	two256 := big.NewInt(1)
	two256.Lsh(two256, 256)
	want := new(big.Int)
	for i := 0; i < numTests; i++ {
		bigX, _ := rand.Int(rand.Reader, two256)
		bigX.Add(bigX, p).Mod(bigX, two256)
		conv.BigInt2BytesLe(x[:], bigX)

		Modp(&x)
		got := conv.BytesLe2BigInt(x[:])

		want.Mod(bigX, p)

		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, bigX)
		}
	}
}

func TestIsZero(t *testing.T) {
	var x Elt
	got := IsZero(&x)
	want := true
	if got != want {
		test.ReportError(t, got, want, x)
	}

	SetOne(&x)
	got = IsZero(&x)
	want = false
	if got != want {
		test.ReportError(t, got, want, x)
	}

	x = P()
	got = IsZero(&x)
	want = true
	if got != want {
		test.ReportError(t, got, want, x)
	}
}

func TestToBytes(t *testing.T) {
	const numTests = 1 << 9
	var x Elt
	var got, want [Size]byte
	for i := 0; i < numTests; i++ {
		_, _ = rand.Read(x[:])
		ToBytes(got[:], &x)
		conv.BigInt2BytesLe(want[:], conv.BytesLe2BigInt(x[:]))

		if got != want {
			test.ReportError(t, got, want, x)
		}
	}
	var small [Size + 1]byte
	defer func() {
		if r := recover(); r == nil {
			got := r
			want := "should panic!"
			test.ReportError(t, got, want)
		}
	}()
	ToBytes(small[:], &x)
}

func TestString(t *testing.T) {
	const numTests = 1 << 9
	var x Elt
	var bigX big.Int
	for i := 0; i < numTests; i++ {
		_, _ = rand.Read(x[:])
		got, _ := bigX.SetString(fmt.Sprint(x), 0)
		want := conv.BytesLe2BigInt(x[:])

		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, x)
		}
	}
}

func TestNeg(t *testing.T) {
	const numTests = 1 << 9
	var x, z Elt
	prime := P()
	p := conv.BytesLe2BigInt(prime[:])
	for i := 0; i < numTests; i++ {
		_, _ = rand.Read(x[:])
		Neg(&z, &x)
		Modp(&z)
		got := conv.BytesLe2BigInt(z[:])

		bigX := conv.BytesLe2BigInt(x[:])
		want := bigX.Neg(bigX).Mod(bigX, p)

		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, bigX)
		}
	}
}

func TestInv(t *testing.T) {
	const numTests = 1 << 9
	var x, z Elt
	prime := P()
	p := conv.BytesLe2BigInt(prime[:])
	for i := 0; i < numTests; i++ {
		_, _ = rand.Read(x[:])
		Inv(&z, &x)
		Modp(&z)
		got := conv.BytesLe2BigInt(z[:])

		xx := conv.BytesLe2BigInt(x[:])
		want := xx.ModInverse(xx, p)

		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, x)
		}
	}
}

func TestGeneric(t *testing.T) {
	t.Run("Cmov", func(t *testing.T) { testCmov(t, cmovGeneric) })
	t.Run("Cswap", func(t *testing.T) { testCswap(t, cswapGeneric) })
	t.Run("Add", func(t *testing.T) { testAdd(t, addGeneric) })
	t.Run("Sub", func(t *testing.T) { testSub(t, subGeneric) })
	t.Run("AddSub", func(t *testing.T) { testAddSub(t, addsubGeneric) })
	t.Run("Mul", func(t *testing.T) { testMul(t, mulGeneric) })
	t.Run("Sqr", func(t *testing.T) { testSqr(t, sqrGeneric) })
}

func TestNative(t *testing.T) {
	t.Run("Cmov", func(t *testing.T) { testCmov(t, Cmov) })
	t.Run("Cswap", func(t *testing.T) { testCswap(t, Cswap) })
	t.Run("Add", func(t *testing.T) { testAdd(t, Add) })
	t.Run("Sub", func(t *testing.T) { testSub(t, Sub) })
	t.Run("AddSub", func(t *testing.T) { testAddSub(t, AddSub) })
	t.Run("Mul", func(t *testing.T) { testMul(t, Mul) })
	t.Run("Sqr", func(t *testing.T) { testSqr(t, Sqr) })
}

func BenchmarkFp(b *testing.B) {
	var x, y, z Elt
	_, _ = rand.Read(x[:])
	_, _ = rand.Read(y[:])
	_, _ = rand.Read(z[:])
	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Add(&x, &y, &z)
		}
	})
	b.Run("Sub", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Sub(&x, &y, &z)
		}
	})
	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Mul(&x, &y, &z)
		}
	})
	b.Run("Sqr", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Sqr(&x, &y)
		}
	})
	b.Run("Inv", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Inv(&x, &y)
		}
	})
}
