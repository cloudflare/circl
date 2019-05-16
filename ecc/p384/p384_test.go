package p384

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func TestIsOnCurveTrue(t *testing.T) {
	curve := P384()
	k := make([]byte, 384/8)
	for i := 0; i < 128; i++ {
		_, _ = rand.Read(k)
		x, y := elliptic.P384().ScalarBaseMult(k)

		got := curve.IsOnCurve(x, y)
		want := true
		if got != want {
			test.ReportError(t, got, want, k)
		}

		x = x.Neg(x)
		got = curve.IsOnCurve(x, y)
		want = false
		if got != want {
			test.ReportError(t, got, want, k)
		}
	}
}

func TestAffine(t *testing.T) {
	curve := P384()
	params := elliptic.P384().Params()
	t.Run("Addition", func(t *testing.T) {
		for i := 0; i < 128; i++ {
			K1, _ := rand.Int(rand.Reader, params.N)
			K2, _ := rand.Int(rand.Reader, params.N)
			X1, Y1 := params.ScalarBaseMult(K1.Bytes())
			X2, Y2 := params.ScalarBaseMult(K2.Bytes())
			wantX, wantY := params.Add(X1, Y1, X2, Y2)
			gotX, gotY := curve.Add(X1, Y1, X2, Y2)

			if gotX.Cmp(wantX) != 0 {
				test.ReportError(t, gotX, wantX, K1, K2)
			}
			if gotY.Cmp(wantY) != 0 {
				test.ReportError(t, gotY, wantY)
			}
		}
	})

	t.Run("Double", func(t *testing.T) {
		for i := 0; i < 128; i++ {
			k, _ := rand.Int(rand.Reader, params.N)
			x, y := params.ScalarBaseMult(k.Bytes())
			wantX, wantY := params.Double(x, y)

			gotX, gotY := curve.Double(x, y)

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
	curve := P384()
	params := curve.Params()

	t.Run("toOdd", func(t *testing.T) {
		k := []byte{0xF0}
		oddK, _ := p384.toOdd(k)
		got := len(oddK)
		want := 48
		if got != want {
			test.ReportError(t, got, want)
		}

		oddK[sizeFp-1] = 0x0
		smallOddK, _ := p384.toOdd(oddK)
		got = len(smallOddK)
		want = 48
		if got != want {
			test.ReportError(t, got, want)
		}
	})

	t.Run("k=0", func(t *testing.T) {
		k := []byte{0x0}
		gotX, gotY := curve.ScalarMult(params.Gx, params.Gy, k)
		got := curve.IsAtInfinity(gotX, gotY)
		want := true
		if got != want {
			test.ReportError(t, got, want)
		}
	})

	t.Run("random k", func(t *testing.T) {
		for i := 0; i < 128; i++ {
			k, _ := rand.Int(rand.Reader, params.N)
			gotX, gotY := curve.ScalarMult(params.Gx, params.Gy, k.Bytes())
			wantX, wantY := params.ScalarBaseMult(k.Bytes())

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
	curve := P384()
	params := curve.Params()

	t.Run("0P", func(t *testing.T) {
		k := make([]byte, 500)
		for i := 0; i < len(k); i += 20 {
			gotX, gotY := curve.ScalarBaseMult(k)
			wantX, wantY := params.ScalarBaseMult(k)
			if gotX.Cmp(wantX) != 0 {
				test.ReportError(t, gotX, wantX, k)
			}
			if gotY.Cmp(wantY) != 0 {
				test.ReportError(t, gotY, wantY)
			}
		}
	})

	t.Run("kP", func(t *testing.T) {
		k := make([]byte, 48)
		for i := 0; i < 64; i++ {
			_, _ = rand.Read(k)
			gotX, gotY := p384.ScalarBaseMult(k)
			wantX, wantY := params.ScalarBaseMult(k)
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
		for i := 0; i < 64; i++ {
			_, _ = rand.Read(k)
			gotX, gotY := p384.ScalarBaseMult(k)
			wantX, wantY := params.ScalarBaseMult(k)
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
		for i := 0; i < 64; i++ {
			_, _ = rand.Read(k)
			gotX, gotY := p384.ScalarBaseMult(k)
			wantX, wantY := params.ScalarBaseMult(k)
			if gotX.Cmp(wantX) != 0 {
				test.ReportError(t, gotX, wantX, k)
			}
			if gotY.Cmp(wantY) != 0 {
				test.ReportError(t, gotY, wantY)
			}
		}
	})
}

func TestSimultaneous(t *testing.T) {
	curve := P384()
	params := curve.Params()

	for i := 0; i < 100; i++ {
		K, _ := rand.Int(rand.Reader, params.N)
		X, Y := params.ScalarBaseMult(K.Bytes())

		K1, _ := rand.Int(rand.Reader, params.N)
		K2, _ := rand.Int(rand.Reader, params.N)
		x1, y1 := params.ScalarBaseMult(K1.Bytes())
		x2, y2 := params.ScalarMult(X, Y, K2.Bytes())
		wantX, wantY := params.Add(x1, y1, x2, y2)

		gotX, gotY := curve.SimultaneousMult(X, Y, K1.Bytes(), K2.Bytes())
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

func BenchmarkScalarMult(b *testing.B) {
	curve := P384()
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
			_, _ = curve.SimultaneousMult(params.Gx, params.Gy, m, n)
		}
	})
}
