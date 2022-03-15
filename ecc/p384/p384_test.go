package p384_test

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/ecc/p384"
	"github.com/cloudflare/circl/internal/test"
)

func TestIsOnCurveTrue(t *testing.T) {
	CirclCurve := p384.P384()
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
	CirclCurve := p384.P384()
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

func TestScalarBaseMult(t *testing.T) {
	const testTimes = 1 << 6
	CirclCurve := p384.P384()
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

func TestScalarMult(t *testing.T) {
	const testTimes = 1 << 6
	CirclCurve := p384.P384()
	StdCurve := elliptic.P384()
	params := StdCurve.Params()

	t.Run("k=0", func(t *testing.T) {
		k := []byte{0x0}
		gotX, gotY := CirclCurve.ScalarMult(params.Gx, params.Gy, k)
		got := CirclCurve.IsAtInfinity(gotX, gotY)
		want := true
		if got != want {
			test.ReportError(t, got, want)
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

			got := CirclCurve.IsOnCurve(x, y) && CirclCurve.IsOnCurve(CirclCurve.ScalarMult(x, y, k.Bytes()))
			want := StdCurve.IsOnCurve(x, y) && StdCurve.IsOnCurve(StdCurve.ScalarMult(x, y, k.Bytes()))

			if got != want {
				test.ReportError(t, got, want, k, x, y)
			}
		}
	})
}

func TestCombinedMult(t *testing.T) {
	const testTimes = 1 << 7
	CirclCurve := p384.P384()
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

func BenchmarkScalarMult(b *testing.B) {
	curve := p384.P384()
	params := curve.Params()

	K, _ := rand.Int(rand.Reader, params.N)
	M, _ := rand.Int(rand.Reader, params.N)
	N, _ := rand.Int(rand.Reader, params.N)
	k := K.Bytes()
	m := M.Bytes()
	n := N.Bytes()

	b.Run("kG", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			curve.ScalarBaseMult(k)
		}
	})
	b.Run("kP", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			curve.ScalarMult(params.Gx, params.Gy, k)
		}
	})
	b.Run("kG+lP", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = curve.CombinedMult(params.Gx, params.Gy, m, n)
		}
	})
}

func Example_p384() {
	// import "github.com/cloudflare/circl/ecc/p384"
	// import "crypto/elliptic"
	circl := p384.P384()
	stdlib := elliptic.P384()

	params := circl.Params()
	K, _ := rand.Int(rand.Reader, params.N)
	k := K.Bytes()

	x1, y1 := circl.ScalarBaseMult(k)
	x2, y2 := stdlib.ScalarBaseMult(k)
	fmt.Printf("%v, %v", x1.Cmp(x2) == 0, y1.Cmp(y2) == 0)
	// Output: true, true
}
