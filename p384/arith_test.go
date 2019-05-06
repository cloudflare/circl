package p384

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/utils"
	"github.com/cloudflare/circl/utils/test"
)

func TestFpNegZero(t *testing.T) {
	zero, x := &fp384{}, &fp384{}
	fp384Neg(x, zero)
	got := x.BigInt()
	want := zero.BigInt()
	test.ReportError(t, got, want, x)
}

func TestFpSetBigInt(t *testing.T) {
	P := elliptic.P384().Params().P

	neg := big.NewInt(-0xFF)                       // negative
	zero := big.NewInt(0)                          // zero
	one := big.NewInt(1)                           // one
	two96 := new(big.Int).Lsh(one, 96)             // 2^96
	two384 := new(big.Int).Lsh(one, 384)           // 2^384
	two384two96 := new(big.Int).Sub(two384, two96) // 2^384-2^96
	two768 := new(big.Int).Lsh(one, 768)           // 2^768

	for id, b := range []*big.Int{
		neg, zero, one, two96, two384, two384two96, two768} {
		var x fp384
		x.SetBigInt(b)
		got := x.BigInt()
		if b.BitLen() > 384 || b.Sign() < 0 {
			b.Mod(b, P)
		}
		want := b
		test.ReportError(t, got, want, id)
	}
}

func TestMulZero(t *testing.T) {
	x, zero := &fp384{}, &fp384{}

	// Random numbers
	utils.NonCryptoRand(x[:])

	fp384Mul(x, x, zero)
	got := x.BigInt()
	want := zero.BigInt()

	test.ReportError(t, got, want, x)
}

func TestFp(t *testing.T) {
	P := elliptic.P384().Params().P
	x, y, z := &fp384{}, &fp384{}, &fp384{}
	testTimes := 1 << 12

	var bigR, bigR2, bigRinv big.Int
	one := big.NewInt(1)
	bigR.Lsh(one, 384).Mod(&bigR, P)
	bigR2.Lsh(one, 2*384).Mod(&bigR2, P)
	bigRinv.ModInverse(&bigR, P)

	t.Run("Encode", func(t *testing.T) {
		for i := 0; i < testTimes; i++ {
			// Random numbers
			utils.NonCryptoRand(x[:])
			bigX := x.BigInt()

			// fp384
			montEncode(z, x)
			got := z.BigInt()

			// big.Int
			want := bigX.Mul(bigX, &bigR).Mod(bigX, P)

			test.ReportError(t, got, want, x)
		}
	})

	t.Run("Decode", func(t *testing.T) {
		for i := 0; i < testTimes; i++ {
			// Random numbers
			utils.NonCryptoRand(x[:])
			bigX := x.BigInt()

			// fp384
			montDecode(z, x)
			got := z.BigInt()

			// big.Int
			want := bigX.Mul(bigX, new(big.Int).ModInverse(&bigR, P)).Mod(bigX, P)

			test.ReportError(t, got, want, x)
		}
	})

	t.Run("Neg", func(t *testing.T) {
		for i := 0; i < testTimes; i++ {
			// Random numbers
			utils.NonCryptoRand(x[:])
			bigX := x.BigInt()

			// fp384
			fp384Neg(z, x)
			got := z.BigInt()

			// big.Int
			want := bigX.Neg(bigX).Mod(bigX, P)

			test.ReportError(t, got, want, x)
		}
	})

	t.Run("Add", func(t *testing.T) {
		for i := 0; i < testTimes; i++ {
			// Random numbers
			utils.NonCryptoRand(x[:])
			utils.NonCryptoRand(y[:])
			bigX := x.BigInt()
			bigY := y.BigInt()

			// fp384
			fp384Add(z, x, y)
			got := z.BigInt()

			// big.Int
			want := bigX.Add(bigX, bigY)
			want = want.Mod(want, P)

			test.ReportError(t, got, want, x, y)
		}
	})

	t.Run("Sub", func(t *testing.T) {
		for i := 0; i < testTimes; i++ {
			// Random numbers
			utils.NonCryptoRand(x[:])
			utils.NonCryptoRand(y[:])
			bigX := x.BigInt()
			bigY := y.BigInt()

			// fp384
			fp384Sub(z, x, y)
			got := z.BigInt()

			// big.Int
			want := bigX.Sub(bigX, bigY)
			want = want.Mod(want, P)

			test.ReportError(t, got, want, x, y)
		}
	})

	t.Run("Mul", func(t *testing.T) {
		for i := 0; i < testTimes; i++ {
			// Random numbers
			utils.NonCryptoRand(x[:])
			utils.NonCryptoRand(y[:])
			bigX := x.BigInt()
			bigY := y.BigInt()

			// fp384
			fp384Mul(z, x, y)
			got := z.BigInt()

			// big.Int
			want := bigX.Mul(bigX, bigY).Mul(bigX, &bigRinv).Mod(bigX, P)

			test.ReportError(t, got, want, x, y)
		}
	})

	t.Run("Inv", func(t *testing.T) {
		for i := 0; i < testTimes; i++ {
			// Random numbers
			utils.NonCryptoRand(x[:])
			bigX := x.BigInt()

			// fp384
			fp384Inv(z, x)
			got := z.BigInt()

			// big.Int
			want := bigX.ModInverse(bigX, P).Mul(bigX, &bigR2).Mod(bigX, P)

			test.ReportError(t, got, want, x)
		}
	})
}

func BenchmarkFp(b *testing.B) {
	x, y, z := &fp384{}, &fp384{}, &fp384{}

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fp384Add(z, x, y)
		}
	})

	b.Run("Sub", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fp384Sub(z, x, y)
		}
	})

	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fp384Mul(z, x, y)
		}
	})

	b.Run("Sqr", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fp384Sqr(z, x)
		}
	})

	b.Run("Inv", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fp384Inv(z, x)
		}
	})
}
