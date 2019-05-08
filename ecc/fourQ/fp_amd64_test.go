// +build amd64,go1.12

package fourQ

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func getModulus() *big.Int {
	p := big.NewInt(1)
	return p.Lsh(p, 127).Sub(p, big.NewInt(1))
}

func TestFpSign(t *testing.T) {
	const testTimes = 1 << 9
	P := getModulus()
	x := &Fp{}
	var P1div2 big.Int
	P1div2.Add(P, big.NewInt(1)).Rsh(&P1div2, 1) // (p+1)/2

	// Verifying Sign(0) = 0
	x.setBigInt(big.NewInt(0))
	got := fpSgn(x)
	want := 0
	if got != want {
		test.ReportError(t, got, want, x)
	}

	// Verifying Sign(P) = 0
	x.setBigInt(P)
	got = fpSgn(x)
	want = 0
	if got != want {
		test.ReportError(t, got, want, x)
	}

	// Verifying Sign( (p+1)/2 ) = -1
	x.setBigInt(&P1div2)
	got = fpSgn(x)
	want = -1
	if got != want {
		test.ReportError(t, got, want, x)
	}

	// Verifying x be a non-zero positive
	for i := 0; i < testTimes; i++ {
		bigX, _ := rand.Int(rand.Reader, &P1div2)
		x.setBigInt(bigX)
		got = fpSgn(x)
		want = 1
		if got != want {
			test.ReportError(t, got, want, x)
		}
	}
	// Verifying x be a non-zero negative
	for i := 0; i < testTimes; i++ {
		bigX, _ := rand.Int(rand.Reader, &P1div2)
		bigX.Add(bigX, &P1div2)
		x.setBigInt(bigX)
		got = fpSgn(x)
		want = -1
		if got != want {
			test.ReportError(t, got, want, x)
		}
	}
}

func TestFpIsZero(t *testing.T) {
	P := getModulus()
	x := &Fp{}
	// Verifying x=0
	x.setBigInt(big.NewInt(0))
	got := x.isZero()
	want := true
	if got != want {
		test.ReportError(t, got, want, x)
	}

	// Verifying x=P goes to 0
	x.setBigInt(P)
	got = x.isZero()
	want = true
	if got != want {
		test.ReportError(t, got, want, x)
	}

	// Verifying x!=0
	_, _ = rand.Read(x[:])
	got = x.isZero()
	want = false
	if got != want {
		test.ReportError(t, got, want, x)
	}
}

func TestFpModp(t *testing.T) {
	const testTimes = 1 << 9
	P := getModulus()
	x := &Fp{}
	var bigX big.Int
	// Verifying x=P goes to 0
	bigX.Set(P)
	x.setBigInt(&bigX)
	fpMod(x)
	got := x.toBigInt()
	want := big.NewInt(0)
	if got.Cmp(want) != 0 {
		test.ReportError(t, got, want, x)
	}

	// Verifying x=P+1 goes to 1
	bigX.Add(P, big.NewInt(1))
	x.setBigInt(&bigX)
	fpMod(x)
	got = x.toBigInt()
	want = big.NewInt(1)
	if got.Cmp(want) != 0 {
		test.ReportError(t, got, want, x)
	}

	for i := 0; i < testTimes; i++ {
		_, _ = rand.Read(x[:])

		bigX := x.toBigInt()

		fpMod(x)
		got := x.toBigInt()

		want := bigX.Mod(bigX, P)
		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, x)
		}
	}
}

func TestFpNeg(t *testing.T) {
	const testTimes = 1 << 9
	P := getModulus()
	x, z := &Fp{}, &Fp{}
	for i := 0; i < testTimes; i++ {
		bigX, _ := rand.Int(rand.Reader, P)

		x.setBigInt(bigX)
		fpNeg(z, x)
		got := z.toBigInt()

		want := bigX.Neg(bigX)
		want = want.Mod(want, P)
		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, x)
		}
	}
}

func TestFpHlf(t *testing.T) {
	const testTimes = 1 << 9
	P := getModulus()
	x, z := &Fp{}, &Fp{}
	invTwo := big.NewInt(2)
	invTwo.ModInverse(invTwo, P)
	for i := 0; i < testTimes; i++ {
		bigX, _ := rand.Int(rand.Reader, P)

		x.setBigInt(bigX)
		fpHlf(z, x)
		got := z.toBigInt()

		want := bigX.Mul(bigX, invTwo)
		want = want.Mod(want, P)
		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, x)
		}
	}
}

func TestFpAdd(t *testing.T) {
	const testTimes = 1 << 9
	P := getModulus()
	x, y, z := &Fp{}, &Fp{}, &Fp{}
	for i := 0; i < testTimes; i++ {
		bigX, _ := rand.Int(rand.Reader, P)
		bigY, _ := rand.Int(rand.Reader, P)

		x.setBigInt(bigX)
		y.setBigInt(bigY)
		fpAdd(z, x, y)
		got := z.toBigInt()

		want := bigX.Add(bigX, bigY)
		want = want.Mod(want, P)
		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, x, y)
		}
	}
}

func TestFpSub(t *testing.T) {
	const testTimes = 1 << 9
	P := getModulus()
	x, y, z := &Fp{}, &Fp{}, &Fp{}
	for i := 0; i < testTimes; i++ {
		bigX, _ := rand.Int(rand.Reader, P)
		bigY, _ := rand.Int(rand.Reader, P)

		x.setBigInt(bigX)
		y.setBigInt(bigY)
		fpSub(z, x, y)
		got := z.toBigInt()

		want := bigX.Sub(bigX, bigY)
		want = want.Mod(want, P)
		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, x, y)
		}
	}
}

func TestFpMul(t *testing.T) {
	const testTimes = 1 << 9
	P := getModulus()
	x, y, z := &Fp{}, &Fp{}, &Fp{}
	for i := 0; i < testTimes; i++ {
		bigX, _ := rand.Int(rand.Reader, P)
		bigY, _ := rand.Int(rand.Reader, P)

		x.setBigInt(bigX)
		y.setBigInt(bigY)
		fpMul(z, x, y)
		got := z.toBigInt()

		want := bigX.Mul(bigX, bigY)
		want = want.Mod(want, P)
		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, x, y)
		}
	}
}

func TestFpSqr(t *testing.T) {
	const testTimes = 1 << 9
	P := getModulus()
	x, z := &Fp{}, &Fp{}
	for i := 0; i < testTimes; i++ {
		bigX, _ := rand.Int(rand.Reader, P)

		x.setBigInt(bigX)
		fpSqr(z, x)
		got := z.toBigInt()

		want := bigX.Mul(bigX, bigX)
		want = want.Mod(want, P)

		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, x)
		}
	}
}

func TestFpInv(t *testing.T) {
	const testTimes = 1 << 9
	P := getModulus()
	x, z := &Fp{}, &Fp{}
	for i := 0; i < testTimes; i++ {
		bigX, _ := rand.Int(rand.Reader, P)

		x.setBigInt(bigX)
		fpInv(z, x)
		got := z.toBigInt()

		want := bigX.ModInverse(bigX, P)
		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, x)
		}
	}
}

func BenchmarkFp(b *testing.B) {
	x, y, z := &Fp{}, &Fp{}, &Fp{}
	p := getModulus()
	n, _ := rand.Int(rand.Reader, p)
	x.setBigInt(n)
	n, _ = rand.Int(rand.Reader, p)
	y.setBigInt(n)

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fpAdd(z, x, y)
		}
	})
	b.Run("Sub", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fpSub(z, x, y)
		}
	})
	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fpMul(z, x, y)
		}
	})
	b.Run("Sqr", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fpSqr(z, x)
		}
	})
	b.Run("Inv", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fpInv(z, x)
		}
	})
}
