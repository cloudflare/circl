package fp25519_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/internal/test"
	fp "github.com/cloudflare/circl/math/fp25519"
)

func TestFp(t *testing.T) {
	const numTests = 1 << 9
	var x, y, z fp.Elt
	prime := fp.P()
	p := conv.BytesLe2BigInt(prime[:])

	t.Run("IsZero", func(t *testing.T) {
		fp.SetZero(&x)
		got := fp.IsZero(&x)
		want := true
		if got != want {
			test.ReportError(t, got, want, x)
		}

		fp.SetOne(&x)
		got = fp.IsZero(&x)
		want = false
		if got != want {
			test.ReportError(t, got, want, x)
		}

		x = fp.P()
		got = fp.IsZero(&x)
		want = true
		if got != want {
			test.ReportError(t, got, want, x)
		}

		x = fp.Elt{ // 2P
			0xda, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		}
		got = fp.IsZero(&x)
		want = true
		if got != want {
			test.ReportError(t, got, want, x)
		}
	})
	t.Run("ToBytes", func(t *testing.T) {
		var got, want [fp.Size]byte
		for i := 0; i < numTests; i++ {
			_, _ = rand.Read(x[:])
			fp.ToBytes(got[:], &x)
			conv.BigInt2BytesLe(want[:], conv.BytesLe2BigInt(x[:]))

			if got != want {
				test.ReportError(t, got, want, x)
			}
		}
		var small [fp.Size + 1]byte
		defer func() {
			if r := recover(); r == nil {
				got := r
				want := "should panic!"
				test.ReportError(t, got, want)
			}
		}()
		fp.ToBytes(small[:], &x)
	})
	t.Run("String", func(t *testing.T) {
		var bigX big.Int
		for i := 0; i < numTests; i++ {
			_, _ = rand.Read(x[:])
			s := fmt.Sprint(x)
			got, _ := bigX.SetString(s, 0)
			want := conv.BytesLe2BigInt(x[:])

			if got.Cmp(want) != 0 {
				test.ReportError(t, got, want, x)
			}
		}
	})
	t.Run("Cmov", func(t *testing.T) {
		for i := 0; i < numTests; i++ {
			_, _ = rand.Read(x[:])
			_, _ = rand.Read(y[:])
			b := uint(y[0] & 0x1)
			want := conv.BytesLe2BigInt(x[:])
			if b != 0 {
				want = conv.BytesLe2BigInt(y[:])
			}

			fp.Cmov(&x, &y, b)
			got := conv.BytesLe2BigInt(x[:])

			if got.Cmp(want) != 0 {
				test.ReportError(t, got, want, x, y, b)
			}
		}
	})
	t.Run("Cswap", func(t *testing.T) {
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

			fp.Cswap(&x, &y, b)
			got0 := conv.BytesLe2BigInt(x[:])
			got1 := conv.BytesLe2BigInt(y[:])

			if got0.Cmp(want0) != 0 {
				test.ReportError(t, got0, want0, x, y, b)
			}
			if got1.Cmp(want1) != 0 {
				test.ReportError(t, got1, want1, x, y, b)
			}
		}
	})
	t.Run("Modp", func(t *testing.T) {
		two256 := big.NewInt(1)
		two256.Lsh(two256, 256)
		want := new(big.Int)
		for i := 0; i < numTests; i++ {
			bigX, _ := rand.Int(rand.Reader, two256)
			bigX.Add(bigX, p).Mod(bigX, two256)
			conv.BigInt2BytesLe(x[:], bigX)

			fp.Modp(&x)
			got := conv.BytesLe2BigInt(x[:])

			want.Mod(bigX, p)

			if got.Cmp(want) != 0 {
				test.ReportError(t, got, want, bigX)
			}
		}
	})
	t.Run("Neg", func(t *testing.T) {
		for i := 0; i < numTests; i++ {
			_, _ = rand.Read(x[:])
			fp.Neg(&z, &x)
			fp.Modp(&z)
			got := conv.BytesLe2BigInt(z[:])

			bigX := conv.BytesLe2BigInt(x[:])
			want := bigX.Neg(bigX).Mod(bigX, p)

			if got.Cmp(want) != 0 {
				test.ReportError(t, got, want, bigX)
			}
		}
	})
	t.Run("Add", func(t *testing.T) {
		for i := 0; i < numTests; i++ {
			_, _ = rand.Read(x[:])
			_, _ = rand.Read(y[:])
			fp.Add(&z, &x, &y)
			fp.Modp(&z)
			got := conv.BytesLe2BigInt(z[:])

			xx, yy := conv.BytesLe2BigInt(x[:]), conv.BytesLe2BigInt(y[:])
			want := xx.Add(xx, yy).Mod(xx, p)

			if got.Cmp(want) != 0 {
				test.ReportError(t, got, want, x, y)
			}
		}
	})
	t.Run("Sub", func(t *testing.T) {
		for i := 0; i < numTests; i++ {
			_, _ = rand.Read(x[:])
			_, _ = rand.Read(y[:])
			fp.Sub(&z, &x, &y)
			fp.Modp(&z)
			got := conv.BytesLe2BigInt(z[:])

			xx, yy := conv.BytesLe2BigInt(x[:]), conv.BytesLe2BigInt(y[:])
			want := xx.Sub(xx, yy).Mod(xx, p)

			if got.Cmp(want) != 0 {
				test.ReportError(t, got, want, x, y)
			}
		}
	})
	t.Run("AddSub", func(t *testing.T) {
		want0, want1 := big.NewInt(0), big.NewInt(0)
		for i := 0; i < numTests; i++ {
			_, _ = rand.Read(x[:])
			_, _ = rand.Read(y[:])
			xx, yy := conv.BytesLe2BigInt(x[:]), conv.BytesLe2BigInt(y[:])
			want0.Add(xx, yy).Mod(want0, p)
			want1.Sub(xx, yy).Mod(want1, p)

			fp.AddSub(&x, &y)
			fp.Modp(&x)
			fp.Modp(&y)
			got0 := conv.BytesLe2BigInt(x[:])
			got1 := conv.BytesLe2BigInt(y[:])

			if got0.Cmp(want0) != 0 {
				test.ReportError(t, got0, want0, x, y)
			}
			if got1.Cmp(want1) != 0 {
				test.ReportError(t, got1, want1, x, y)
			}
		}
	})
	t.Run("Mul", func(t *testing.T) {
		for i := 0; i < numTests; i++ {
			_, _ = rand.Read(x[:])
			_, _ = rand.Read(y[:])
			fp.Mul(&z, &x, &y)
			fp.Modp(&z)
			got := conv.BytesLe2BigInt(z[:])

			xx, yy := conv.BytesLe2BigInt(x[:]), conv.BytesLe2BigInt(y[:])
			want := xx.Mul(xx, yy).Mod(xx, p)

			if got.Cmp(want) != 0 {
				test.ReportError(t, got, want, x, y)
			}
		}
	})
	t.Run("Sqr", func(t *testing.T) {
		for i := 0; i < numTests; i++ {
			_, _ = rand.Read(x[:])
			fp.Sqr(&z, &x)
			fp.Modp(&z)
			got := conv.BytesLe2BigInt(z[:])

			xx := conv.BytesLe2BigInt(x[:])
			want := xx.Mul(xx, xx).Mod(xx, p)

			if got.Cmp(want) != 0 {
				test.ReportError(t, got, want, x)
			}
		}
	})
	t.Run("Inv", func(t *testing.T) {
		for i := 0; i < numTests; i++ {
			_, _ = rand.Read(x[:])
			fp.Inv(&z, &x)
			fp.Modp(&z)
			got := conv.BytesLe2BigInt(z[:])

			xx := conv.BytesLe2BigInt(x[:])
			want := xx.ModInverse(xx, p)

			if got.Cmp(want) != 0 {
				test.ReportError(t, got, want, x)
			}
		}
	})
}

func BenchmarkFp(b *testing.B) {
	var x, y, z fp.Elt
	_, _ = rand.Read(x[:])
	_, _ = rand.Read(y[:])
	_, _ = rand.Read(z[:])
	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fp.Add(&x, &y, &z)
		}
	})
	b.Run("Sub", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fp.Sub(&x, &y, &z)
		}
	})
	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fp.Mul(&x, &y, &z)
		}
	})
	b.Run("Sqr", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fp.Sqr(&x, &y)
		}
	})
	b.Run("Inv", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fp.Inv(&x, &y)
		}
	})
}
