// +build arm64 amd64

package p384

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func TestIsOnCurveTrue(t *testing.T) {
	CirclCurve := P384()
	k := make([]byte, 384/8)
	for i := 0; i < 128; i++ {
		_, _ = rand.Read(k)
		x, y := elliptic.P384().ScalarBaseMult(k)

		got := CirclCurve.IsOnCurve(x, y)
		want := true
		if got != want {
			test.ReportError(t, got, want, k)
		}

		x = x.Neg(x)
		got = CirclCurve.IsOnCurve(x, y)
		want = false
		if got != want {
			test.ReportError(t, got, want, k)
		}
	}
}

func TestAffine(t *testing.T) {
	const testTimes = 1 << 7
	CirclCurve := P384()
	StdCurve := elliptic.P384()
	params := StdCurve.Params()

	t.Run("Addition", func(t *testing.T) {
		for i := 0; i < testTimes; i++ {
			K1, _ := rand.Int(rand.Reader, params.N)
			K2, _ := rand.Int(rand.Reader, params.N)
			X1, Y1 := StdCurve.ScalarBaseMult(K1.Bytes())
			X2, Y2 := StdCurve.ScalarBaseMult(K2.Bytes())
			wantX, wantY := StdCurve.Add(X1, Y1, X2, Y2)
			gotX, gotY := CirclCurve.Add(X1, Y1, X2, Y2)

			if gotX.Cmp(wantX) != 0 {
				test.ReportError(t, gotX, wantX, K1, K2)
			}
			if gotY.Cmp(wantY) != 0 {
				test.ReportError(t, gotY, wantY)
			}
		}
	})

	t.Run("Double", func(t *testing.T) {
		for i := 0; i < testTimes; i++ {
			k, _ := rand.Int(rand.Reader, params.N)
			x, y := StdCurve.ScalarBaseMult(k.Bytes())
			wantX, wantY := StdCurve.Double(x, y)

			gotX, gotY := CirclCurve.Double(x, y)

			if gotX.Cmp(wantX) != 0 {
				test.ReportError(t, gotX, wantX, k)
			}
			if gotY.Cmp(wantY) != 0 {
				test.ReportError(t, gotY, wantY)
			}
		}
	})
}

func TestScalarMult(t *testing.T) {
	const testTimes = 1 << 7
	CirclCurve := P384()
	StdCurve := elliptic.P384()
	params := StdCurve.Params()

	t.Run("toOdd", func(t *testing.T) {
		var c curve
		k := []byte{0xF0}
		oddK, _ := c.toOdd(k)
		got := len(oddK)
		want := 48
		if got != want {
			test.ReportError(t, got, want)
		}

		oddK[sizeFp-1] = 0x0
		smallOddK, _ := c.toOdd(oddK)
		got = len(smallOddK)
		want = 48
		if got != want {
			test.ReportError(t, got, want)
		}
	})

	t.Run("k=0", func(t *testing.T) {
		k := []byte{0x0}
		gotX, gotY := CirclCurve.ScalarMult(params.Gx, params.Gy, k)
		got := CirclCurve.IsAtInfinity(gotX, gotY)
		want := true
		if got != want {
			test.ReportError(t, got, want)
		}
	})

	t.Run("special k", func(t *testing.T) {
		cases := []struct { // known cases that require complete addition
			w uint
			k int
		}{
			{w: 2, k: 2},
			{w: 5, k: 6},
			{w: 6, k: 38},
			{w: 7, k: 102},
			{w: 9, k: 230},
			{w: 12, k: 742},
			{w: 14, k: 4838},
			{w: 17, k: 21222},
			{w: 19, k: 152294},
		}

		var c curve

		for _, caseI := range cases {
			k := big.NewInt(int64(caseI.k)).Bytes()
			gotX, gotY := c.scalarMultOmega(params.Gx, params.Gy, k, caseI.w)
			wantX, wantY := StdCurve.ScalarMult(params.Gx, params.Gy, k)

			if gotX.Cmp(wantX) != 0 {
				test.ReportError(t, gotX, wantX, caseI)
			}
			if gotY.Cmp(wantY) != 0 {
				test.ReportError(t, gotY, wantY, caseI)
			}
		}
	})

	t.Run("random k", func(t *testing.T) {
		for i := 0; i < testTimes; i++ {
			k, _ := rand.Int(rand.Reader, params.N)
			gotX, gotY := CirclCurve.ScalarMult(params.Gx, params.Gy, k.Bytes())
			wantX, wantY := StdCurve.ScalarMult(params.Gx, params.Gy, k.Bytes())

			if gotX.Cmp(wantX) != 0 {
				test.ReportError(t, gotX, wantX, k)
			}
			if gotY.Cmp(wantY) != 0 {
				test.ReportError(t, gotY, wantY)
			}
		}
	})

	t.Run("wrong P", func(t *testing.T) {
		for i := 0; i < testTimes; i++ {
			k, _ := rand.Int(rand.Reader, params.N)
			x, _ := rand.Int(rand.Reader, params.P)
			y, _ := rand.Int(rand.Reader, params.P)

			got := CirclCurve.IsOnCurve(CirclCurve.ScalarMult(x, y, k.Bytes()))
			want := StdCurve.IsOnCurve(StdCurve.ScalarMult(x, y, k.Bytes()))

			if got != want {
				test.ReportError(t, got, want, k, x, y)
			}
		}
	})
}

func TestScalarBaseMult(t *testing.T) {
	const testTimes = 1 << 7
	CirclCurve := P384()
	StdCurve := elliptic.P384()

	t.Run("0P", func(t *testing.T) {
		k := make([]byte, 500)
		for i := 0; i < len(k); i += 20 {
			gotX, gotY := CirclCurve.ScalarBaseMult(k[:i])
			wantX, wantY := StdCurve.ScalarBaseMult(k[:i])
			if gotX.Cmp(wantX) != 0 {
				test.ReportError(t, gotX, wantX, k[:i])
			}
			if gotY.Cmp(wantY) != 0 {
				test.ReportError(t, gotY, wantY)
			}
		}
	})

	t.Run("kP", func(t *testing.T) {
		k := make([]byte, 48)
		for i := 0; i < testTimes; i++ {
			_, _ = rand.Read(k)
			gotX, gotY := CirclCurve.ScalarBaseMult(k)
			wantX, wantY := StdCurve.ScalarBaseMult(k)
			if gotX.Cmp(wantX) != 0 {
				test.ReportError(t, gotX, wantX, k)
			}
			if gotY.Cmp(wantY) != 0 {
				test.ReportError(t, gotY, wantY)
			}
		}
	})

	t.Run("kSmall", func(t *testing.T) {
		k := make([]byte, 16)
		for i := 0; i < testTimes; i++ {
			_, _ = rand.Read(k)
			gotX, gotY := CirclCurve.ScalarBaseMult(k)
			wantX, wantY := StdCurve.ScalarBaseMult(k)
			if gotX.Cmp(wantX) != 0 {
				test.ReportError(t, gotX, wantX, k)
			}
			if gotY.Cmp(wantY) != 0 {
				test.ReportError(t, gotY, wantY)
			}
		}
	})

	t.Run("kLarge", func(t *testing.T) {
		k := make([]byte, 384)
		for i := 0; i < testTimes; i++ {
			_, _ = rand.Read(k)
			gotX, gotY := CirclCurve.ScalarBaseMult(k)
			wantX, wantY := StdCurve.ScalarBaseMult(k)
			if gotX.Cmp(wantX) != 0 {
				test.ReportError(t, gotX, wantX, k)
			}
			if gotY.Cmp(wantY) != 0 {
				test.ReportError(t, gotY, wantY)
			}
		}
	})
}

func TestCombinedMult(t *testing.T) {
	const testTimes = 1 << 7
	CirclCurve := P384()
	StdCurve := elliptic.P384()
	params := StdCurve.Params()

	for i := 0; i < testTimes; i++ {
		K, _ := rand.Int(rand.Reader, params.N)
		X, Y := StdCurve.ScalarBaseMult(K.Bytes())

		K1, _ := rand.Int(rand.Reader, params.N)
		K2, _ := rand.Int(rand.Reader, params.N)
		x1, y1 := StdCurve.ScalarBaseMult(K1.Bytes())
		x2, y2 := StdCurve.ScalarMult(X, Y, K2.Bytes())
		wantX, wantY := StdCurve.Add(x1, y1, x2, y2)

		gotX, gotY := CirclCurve.CombinedMult(X, Y, K1.Bytes(), K2.Bytes())
		if gotX.Cmp(wantX) != 0 {
			test.ReportError(t, gotX, wantX, K, K1, K2)
		}
		if gotY.Cmp(wantY) != 0 {
			test.ReportError(t, gotY, wantY)
		}
	}
}

func TestAbsoute(t *testing.T) {
	cases := []int32{-2, -1, 0, 1, 2}
	expected := []int32{2, 1, 0, 1, 2}
	for i := range cases {
		got := absolute(cases[i])
		want := expected[i]
		if got != want {
			test.ReportError(t, got, want, cases[i])
		}
	}
}
