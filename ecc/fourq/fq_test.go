// +build amd64,go1.12

package fourq

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func TestFqOne(t *testing.T) {
	x := &Fq{}
	x.setOne()
	got0, got1 := x.toBigInt()
	want0, want1 := big.NewInt(1), big.NewInt(0)
	if got0.Cmp(want0) != 0 {
		test.ReportError(t, got0, want0, x)
	}
	if got1.Cmp(want1) != 0 {
		test.ReportError(t, got1, want1, x)
	}
}

func TestFqSign(t *testing.T) {
	testTimes := 1 << 9
	x := &Fq{}
	P := getModulus()
	var P1div2 big.Int
	P1div2.Add(P, big.NewInt(1)).Rsh(&P1div2, 1) // (p+1)/2

	// Verifying Sign(0) = 0
	x.setBigInt(big.NewInt(0), big.NewInt(0))
	got := fqSgn(x)
	want := 0
	if got != want {
		test.ReportError(t, got, want, x)
	}

	// Verifying Sign(P) = 0
	x.setBigInt(P, P)
	got = fqSgn(x)
	want = 0
	if got != want {
		test.ReportError(t, got, want, x)
	}

	// Verifying Sign( (p+1)/2 ) = -1
	x.setBigInt(&P1div2, &P1div2)
	got = fqSgn(x)
	want = -1
	if got != want {
		test.ReportError(t, got, want, x)
	}

	// Verifying x be a non-zero positive
	for i := 0; i < testTimes; i++ {
		bigX1, _ := rand.Int(rand.Reader, &P1div2)
		x.setBigInt(P, bigX1)
		got = fqSgn(x)
		want = 1
		if got != want {
			test.ReportError(t, got, want, x)
		}
	}
	// Verifying x be a non-zero positive
	for i := 0; i < testTimes; i++ {
		bigX0, _ := rand.Int(rand.Reader, &P1div2)
		bigX1, _ := rand.Int(rand.Reader, &P1div2)
		x.setBigInt(bigX0, bigX1)
		got = fqSgn(x)
		want = 1
		if got != want {
			test.ReportError(t, got, want, x)
		}
	}
	// Verifying x be a non-zero negative
	for i := 0; i < testTimes; i++ {
		bigX1, _ := rand.Int(rand.Reader, &P1div2)
		bigX1.Add(bigX1, &P1div2)
		x.setBigInt(P, bigX1)
		got = fqSgn(x)
		want = -1
		if got != want {
			test.ReportError(t, got, want, x)
		}
	}
	// Verifying x be a non-zero negative
	for i := 0; i < testTimes; i++ {
		bigX0, _ := rand.Int(rand.Reader, &P1div2)
		bigX1, _ := rand.Int(rand.Reader, &P1div2)
		bigX0.Add(bigX0, &P1div2)
		bigX1.Add(bigX1, &P1div2)
		x.setBigInt(bigX0, bigX1)
		got = fqSgn(x)
		want = -1
		if got != want {
			test.ReportError(t, got, want, x)
		}
	}
}

func TestFqIsZero(t *testing.T) {
	x := &Fq{}
	P := getModulus()
	// Verifying x=0
	x.setBigInt(big.NewInt(0), big.NewInt(0))
	got := x.isZero()
	want := true
	if got != want {
		test.ReportError(t, got, want, x)
	}

	// Verifying x=P goes to 0
	x.setBigInt(P, P)
	got = x.isZero()
	want = true
	if got != want {
		test.ReportError(t, got, want, x)
	}

	// Verifying x!=0
	bigX0, _ := rand.Int(rand.Reader, P)
	bigX1, _ := rand.Int(rand.Reader, P)
	x.setBigInt(bigX0, bigX1)
	got = x.isZero()
	want = false
	if got != want {
		test.ReportError(t, got, want, x)
	}
}

func TestFqNeg(t *testing.T) {
	testTimes := 1 << 9
	x, z := &Fq{}, &Fq{}
	P := getModulus()
	for i := 0; i < testTimes; i++ {
		bigX0, _ := rand.Int(rand.Reader, P)
		bigX1, _ := rand.Int(rand.Reader, P)

		x.setBigInt(bigX0, bigX1)
		fqNeg(z, x)
		got0, got1 := z.toBigInt()

		want0 := bigX0.Neg(bigX0)
		want1 := bigX1.Neg(bigX1)
		want0 = want0.Mod(want0, P)
		want1 = want1.Mod(want1, P)
		if got0.Cmp(want0) != 0 {
			test.ReportError(t, got0, want0, x)
		}
		if got1.Cmp(want1) != 0 {
			test.ReportError(t, got1, want1, x)
		}
	}
}

func TestFqAdd(t *testing.T) {
	testTimes := 1 << 9
	x, y, z := &Fq{}, &Fq{}, &Fq{}
	P := getModulus()
	for i := 0; i < testTimes; i++ {
		bigX0, _ := rand.Int(rand.Reader, P)
		bigX1, _ := rand.Int(rand.Reader, P)
		bigY0, _ := rand.Int(rand.Reader, P)
		bigY1, _ := rand.Int(rand.Reader, P)

		x.setBigInt(bigX0, bigX1)
		y.setBigInt(bigY0, bigY1)
		fqAdd(z, x, y)
		got0, got1 := z.toBigInt()

		want0 := bigX0.Add(bigX0, bigY0)
		want1 := bigX1.Add(bigX1, bigY1)
		want0 = want0.Mod(want0, P)
		want1 = want1.Mod(want1, P)

		if got0.Cmp(want0) != 0 {
			test.ReportError(t, got0, want0, x, y)
		}
		if got1.Cmp(want1) != 0 {
			test.ReportError(t, got1, want1, x, y)
		}
	}
}

func TestFqSub(t *testing.T) {
	testTimes := 1 << 9
	x, y, z := &Fq{}, &Fq{}, &Fq{}
	P := getModulus()
	for i := 0; i < testTimes; i++ {
		bigX0, _ := rand.Int(rand.Reader, P)
		bigX1, _ := rand.Int(rand.Reader, P)
		bigY0, _ := rand.Int(rand.Reader, P)
		bigY1, _ := rand.Int(rand.Reader, P)

		x.setBigInt(bigX0, bigX1)
		y.setBigInt(bigY0, bigY1)
		fqSub(z, x, y)
		got0, got1 := z.toBigInt()

		want0 := bigX0.Sub(bigX0, bigY0)
		want1 := bigX1.Sub(bigX1, bigY1)
		want0 = want0.Mod(want0, P)
		want1 = want1.Mod(want1, P)

		if got0.Cmp(want0) != 0 {
			test.ReportError(t, got0, want0, x, y)
		}
		if got1.Cmp(want1) != 0 {
			test.ReportError(t, got1, want1, x, y)
		}
	}
}

func TestFqMul(t *testing.T) {
	testTimes := 1 << 9
	x, y, z := &Fq{}, &Fq{}, &Fq{}
	P := getModulus()
	for i := 0; i < testTimes; i++ {
		bigX0, _ := rand.Int(rand.Reader, P)
		bigX1, _ := rand.Int(rand.Reader, P)
		bigY0, _ := rand.Int(rand.Reader, P)
		bigY1, _ := rand.Int(rand.Reader, P)

		x.setBigInt(bigX0, bigX1)
		y.setBigInt(bigY0, bigY1)
		fqMul(z, x, y)
		got0, got1 := z.toBigInt()

		x0y0 := new(big.Int).Mul(bigX0, bigY0)
		x0y1 := new(big.Int).Mul(bigX0, bigY1)
		x1y0 := new(big.Int).Mul(bigX1, bigY0)
		x1y1 := new(big.Int).Mul(bigX1, bigY1)
		want0 := x0y0.Sub(x0y0, x1y1)
		want1 := x1y0.Add(x1y0, x0y1)
		want0 = want0.Mod(want0, P)
		want1 = want1.Mod(want1, P)

		if got0.Cmp(want0) != 0 {
			test.ReportError(t, got0, want0, x, y)
		}
		if got1.Cmp(want1) != 0 {
			test.ReportError(t, got1, want1, x, y)
		}
	}
}

func TestFqSqr(t *testing.T) {
	testTimes := 1 << 9
	x, z := &Fq{}, &Fq{}
	P := getModulus()
	for i := 0; i < testTimes; i++ {
		bigX0, _ := rand.Int(rand.Reader, P)
		bigX1, _ := rand.Int(rand.Reader, P)

		x.setBigInt(bigX0, bigX1)
		fqSqr(z, x)
		got0, got1 := z.toBigInt()

		x0x0 := new(big.Int).Mul(bigX0, bigX0)
		x0x1 := new(big.Int).Mul(bigX0, bigX1)
		x1x1 := new(big.Int).Mul(bigX1, bigX1)
		want0 := x0x0.Sub(x0x0, x1x1)
		want1 := x0x1.Lsh(x0x1, 1)
		want0 = want0.Mod(want0, P)
		want1 = want1.Mod(want1, P)

		if got0.Cmp(want0) != 0 {
			test.ReportError(t, got0, want0, x)
		}
		if got1.Cmp(want1) != 0 {
			test.ReportError(t, got1, want1, x)
		}
	}
}

func TestFqInv(t *testing.T) {
	testTimes := 1 << 9
	x, z := &Fq{}, &Fq{}
	P := getModulus()
	for i := 0; i < testTimes; i++ {
		bigX0, _ := rand.Int(rand.Reader, P)
		bigX1, _ := rand.Int(rand.Reader, P)

		x.setBigInt(bigX0, bigX1)
		fqInv(z, x)
		got0, got1 := z.toBigInt()

		x0x0 := new(big.Int).Mul(bigX0, bigX0)
		x1x1 := new(big.Int).Mul(bigX1, bigX1)
		inv := x0x0.Add(x0x0, x1x1)
		inv.ModInverse(inv, P)
		want0 := bigX0.Mul(bigX0, inv)
		want1 := bigX1.Mul(bigX1, inv).Neg(bigX1)
		want0 = want0.Mod(want0, P)
		want1 = want1.Mod(want1, P)

		if got0.Cmp(want0) != 0 {
			test.ReportError(t, got0, want0, x)
		}
		if got1.Cmp(want1) != 0 {
			test.ReportError(t, got1, want1, x)
		}
	}
}

func BenchmarkFq(b *testing.B) {
	x, y, z := &Fq{}, &Fq{}, &Fq{}

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fqAdd(z, x, y)
		}
	})
	b.Run("Sub", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fqSub(z, x, y)
		}
	})
	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fqMul(z, x, y)
		}
	})
	b.Run("Sqr", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fqSqr(z, x)
		}
	})
	b.Run("Inv", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fqInv(z, x)
		}
	})
	b.Run("Sqrt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fqSqrt(z, x, y, 1)
		}
	})
}
