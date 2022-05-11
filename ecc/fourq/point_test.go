package fourq

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/internal/test"
)

func (P *pointR1) random() {
	var k [Size]byte
	_, _ = rand.Read(k[:])
	P.ScalarBaseMult(&k)
}

func TestPointAddition(t *testing.T) {
	const testTimes = 1 << 10
	var P, Q pointR1
	_16P := &pointR1{}
	S := &pointR2{}
	for i := 0; i < testTimes; i++ {
		P.random()
		_16P.copy(&P)
		S.FromR1(&P)
		// 16P = 2^4P
		for j := 0; j < 4; j++ {
			_16P.double()
		}
		// 16P = P+P...+P
		Q.SetIdentity()
		for j := 0; j < 16; j++ {
			Q.add(S)
		}
		got := _16P.isEqual(&Q)
		want := true
		if got != want {
			test.ReportError(t, got, want, P)
		}
	}
}

func TestOddMultiples(t *testing.T) {
	const testTimes = 1 << 10
	var P, Q, R pointR1
	var Tab [8]pointR2
	for i := 0; i < testTimes; i++ {
		P.random()
		// T = [1P, 3P, 5P, 7P, 9P, 11P, 13P, 15P]
		P.oddMultiples(&Tab)
		// Q = sum of all T[i] == 64P
		Q.SetIdentity()
		for j := range Tab {
			Q.add(&Tab[j])
		}
		// R = (2^6)P == 64P
		for j := 0; j < 6; j++ {
			R.double()
		}
		got := Q.isEqual(&R)
		want := true
		if got != want {
			test.ReportError(t, got, want, P)
		}
	}
}

func TestScalarMult(t *testing.T) {
	const testTimes = 1 << 10
	var P, Q, G pointR1
	var k [Size]byte

	t.Run("0P=0", func(t *testing.T) {
		for i := 0; i < testTimes; i++ {
			P.random()
			Q.ScalarMult(&k, &P)
			got := Q.IsIdentity()
			want := true
			if got != want {
				test.ReportError(t, got, want, P)
			}
		}
	})
	t.Run("order*P=0", func(t *testing.T) {
		conv.BigInt2BytesLe(k[:], conv.Uint64Le2BigInt(orderGenerator[:]))
		for i := 0; i < testTimes; i++ {
			P.random()
			Q.ScalarMult(&k, &P)
			got := Q.IsIdentity()
			want := true
			if got != want {
				test.ReportError(t, got, want, P)
			}
		}
	})
	t.Run("cofactor*P=clear(P)", func(t *testing.T) {
		conv.BigInt2BytesLe(k[:], big.NewInt(392))
		for i := 0; i < testTimes; i++ {
			P.random()
			Q.ScalarMult(&k, &P)
			P.ClearCofactor()
			got := Q.isEqual(&P)
			want := true
			if got != want {
				test.ReportError(t, got, want, P)
			}
		}
	})
	t.Run("mult", func(t *testing.T) {
		G.X = genX
		G.Y = genY
		for i := 0; i < testTimes; i++ {
			_, _ = rand.Read(k[:])
			P.ScalarMult(&k, &G)
			Q.ScalarBaseMult(&k)
			got := Q.isEqual(&P)
			want := true
			if got != want {
				test.ReportError(t, got, want, k)
			}
		}
	})
}

func TestScalar(t *testing.T) {
	const testTimes = 1 << 12
	var xx [5]uint64
	two256 := big.NewInt(1)
	two256.Lsh(two256, 256)
	two64 := big.NewInt(1)
	two64.Lsh(two64, 64)
	bigOrder := conv.Uint64Le2BigInt(orderGenerator[:])

	t.Run("subYdiv16", func(t *testing.T) {
		want := new(big.Int)
		for i := 0; i < testTimes; i++ {
			bigX, _ := rand.Int(rand.Reader, two256)
			conv.BigInt2Uint64Le(xx[:], bigX)
			x := xx
			bigY, _ := rand.Int(rand.Reader, two64)
			y := bigY.Int64()
			bigY.SetInt64(y)

			subYDiv16(&x, y)
			got := conv.Uint64Le2BigInt(x[:])

			want.Sub(bigX, bigY).Rsh(want, 4)

			if got.Cmp(want) != 0 {
				test.ReportError(t, got, want, bigX, y)
			}
		}
	})

	t.Run("div2subY", func(t *testing.T) {
		want := new(big.Int)
		for i := 0; i < testTimes; i++ {
			bigX, _ := rand.Int(rand.Reader, two256)
			conv.BigInt2Uint64Le(xx[:], bigX)
			x := xx
			bigY, _ := rand.Int(rand.Reader, two64)
			y := bigY.Int64()
			bigY.SetInt64(y)

			div2subY(&x, y)
			got := conv.Uint64Le2BigInt(x[:])

			want.Rsh(bigX, 1).Sub(want, bigY)

			if got.Cmp(want) != 0 {
				test.ReportError(t, got, want, bigX, y)
			}
		}
	})

	t.Run("condAddOrderN", func(t *testing.T) {
		for i := 0; i < testTimes; i++ {
			bigX, _ := rand.Int(rand.Reader, two256)
			conv.BigInt2Uint64Le(xx[:], bigX)
			x := xx

			condAddOrderN(&x)
			got := conv.Uint64Le2BigInt(x[:])

			want := bigX
			if want.Bit(0) == 0 {
				want.Add(want, bigOrder)
			}

			if got.Cmp(want) != 0 {
				test.ReportError(t, got, want, x)
			}
		}
	})

	t.Run("recode", func(t *testing.T) {
		var k [32]byte
		var d [65]int8
		got := new(big.Int)
		for i := 0; i < testTimes; i++ {
			_, _ = rand.Read(k[:])

			recodeScalar(&d, &k)
			got.SetInt64(0)
			for j := len(d) - 1; j >= 0; j-- {
				got.Lsh(got, 4).Add(got, big.NewInt(int64(d[j])))
			}

			want := conv.BytesLe2BigInt(k[:])
			if want.Bit(0) == 0 {
				want.Add(want, bigOrder)
			}

			if got.Cmp(want) != 0 {
				test.ReportError(t, got, want, k)
			}
		}
	})
}

func BenchmarkPoint(b *testing.B) {
	var P, R pointR1
	var Q pointR2
	var k [Size]byte

	_, _ = rand.Read(k[:])

	P.random()
	R.random()
	Q.FromR1(&R)
	R.random()

	b.Run("affine", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.ToAffine()
		}
	})
	b.Run("double", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.double()
		}
	})
	b.Run("add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.add(&Q)
		}
	})
	b.Run("scmulBase", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.ScalarBaseMult(&k)
		}
	})
	b.Run("scmul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.ScalarMult(&k, &R)
		}
	})
}
