package p384_test

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/p384"
	"github.com/cloudflare/circl/utils/test"
)

func TestIsOnCurveTrue(t *testing.T) {
	k := make([]byte, 384/8)
	var c p384.Curve
	for i := 0; i < 128; i++ {
		_, _ = rand.Read(k)
		x, y := elliptic.P384().ScalarBaseMult(k)

		got := c.IsOnCurve(x, y)
		want := true
		test.ReportError(t, got, want, k)

		x = x.Neg(x)
		got = c.IsOnCurve(x, y)
		want = false
		test.ReportError(t, got, want, k)
	}
}

func TestAffine(t *testing.T) {
	params := elliptic.P384().Params()
	var c p384.Curve
	t.Run("Addition", func(t *testing.T) {
		for i := 0; i < 128; i++ {
			K1, _ := rand.Int(rand.Reader, params.N)
			K2, _ := rand.Int(rand.Reader, params.N)
			X1, Y1 := params.ScalarBaseMult(K1.Bytes())
			X2, Y2 := params.ScalarBaseMult(K2.Bytes())
			wantX, wantY := params.Add(X1, Y1, X2, Y2)

			gotX, gotY := c.Add(X1, Y1, X2, Y2)

			test.ReportError(t, gotX, wantX, K1, K2)
			test.ReportError(t, gotY, wantY)
		}
	})

	t.Run("Double", func(t *testing.T) {
		for i := 0; i < 128; i++ {
			k, _ := rand.Int(rand.Reader, params.N)
			x, y := params.ScalarBaseMult(k.Bytes())
			wantX, wantY := params.Double(x, y)

			gotX, gotY := c.Double(x, y)

			test.ReportError(t, gotX, wantX, k)
			test.ReportError(t, gotY, wantY)
		}
	})
}

func TestScalarMult(t *testing.T) {
	params := elliptic.P384().Params()
	var c p384.Curve

	for i := 0; i < 128; i++ {
		k, _ := rand.Int(rand.Reader, params.N)
		wantX, wantY := params.ScalarBaseMult(k.Bytes())

		gotX, gotY := c.ScalarMult(params.Gx, params.Gy, k.Bytes())

		test.ReportError(t, gotX, wantX, k)
		test.ReportError(t, gotY, wantY)
	}
}

func TestScalarBaseMult(t *testing.T) {
	var c p384.Curve
	params := elliptic.P384().Params()
	t.Run("0P", func(t *testing.T) {
		k := make([]byte, 500)
		for i := 0; i < len(k); i += 20 {
			gotX, gotY := c.ScalarBaseMult(k)
			wantX, wantY := params.ScalarBaseMult(k)
			test.ReportError(t, gotX, wantX)
			test.ReportError(t, gotY, wantY)
		}
	})

	t.Run("kP", func(t *testing.T) {
		k := make([]byte, 48)
		for i := 0; i < 64; i++ {
			_, _ = rand.Read(k)
			gotX, gotY := c.ScalarBaseMult(k)
			wantX, wantY := params.ScalarBaseMult(k)
			test.ReportError(t, gotX, wantX, k)
			test.ReportError(t, gotY, wantY)
		}
	})

	t.Run("kSmall", func(t *testing.T) {
		k := make([]byte, 16)
		for i := 0; i < 64; i++ {
			_, _ = rand.Read(k)
			gotX, gotY := c.ScalarBaseMult(k)
			wantX, wantY := params.ScalarBaseMult(k)
			test.ReportError(t, gotX, wantX, k)
			test.ReportError(t, gotY, wantY)
		}
	})

	t.Run("kLarge", func(t *testing.T) {
		k := make([]byte, 384)
		for i := 0; i < 64; i++ {
			_, _ = rand.Read(k)
			gotX, gotY := c.ScalarBaseMult(k)
			wantX, wantY := params.ScalarBaseMult(k)
			test.ReportError(t, gotX, wantX, k)
			test.ReportError(t, gotY, wantY)
		}
	})
}

func TestSimultaneous(t *testing.T) {
	var c p384.Curve
	params := elliptic.P384().Params()

	for i := 0; i < 100; i++ {
		K, _ := rand.Int(rand.Reader, params.N)
		X, Y := params.ScalarBaseMult(K.Bytes())

		K1, _ := rand.Int(rand.Reader, params.N)
		K2, _ := rand.Int(rand.Reader, params.N)
		x1, y1 := params.ScalarBaseMult(K1.Bytes())
		x2, y2 := params.ScalarMult(X, Y, K2.Bytes())
		wantX, wantY := params.Add(x1, y1, x2, y2)

		gotX, gotY := c.SimultaneousMult(X, Y, K1.Bytes(), K2.Bytes())

		test.ReportError(t, gotX, wantX, K, K1, K2)
		test.ReportError(t, gotY, wantY)
	}
}

func BenchmarkP384(b *testing.B) {
	c := elliptic.P384()
	params := c.Params()
	K, _ := rand.Int(rand.Reader, params.N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.ScalarMult(params.Gx, params.Gy, K.Bytes())
	}
}

func BenchmarkScalarMult(b *testing.B) {
	var c p384.Curve
	params := elliptic.P384().Params()
	K, _ := rand.Int(rand.Reader, params.N)
	k := K.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.ScalarMult(params.Gx, params.Gy, k)
	}
}

func BenchmarkScalarBaseMult(b *testing.B) {
	var c p384.Curve
	params := elliptic.P384().Params()
	K, _ := rand.Int(rand.Reader, params.N)
	k := K.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.ScalarBaseMult(k)
	}
}

func BenchmarkSimultaneous(b *testing.B) {
	var c p384.Curve
	params := c.Params()
	x, _ := rand.Int(rand.Reader, params.P)
	y, _ := rand.Int(rand.Reader, params.P)
	M, _ := rand.Int(rand.Reader, params.N)
	N, _ := rand.Int(rand.Reader, params.N)
	m := M.Bytes()
	n := N.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.SimultaneousMult(x, y, m, n)
	}
}
