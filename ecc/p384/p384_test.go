package p384

import (
	"testing"

	"crypto/elliptic"
	"crypto/rand"
)

func TestIsOnCurveTrue(t *testing.T) {
	for i := 0; i < 100; i++ {
		K := make([]byte, 384/8)
		rand.Read(K)

		X, Y := elliptic.P384().ScalarBaseMult(K)

		c := &Curve{}
		if !c.IsOnCurve(X, Y) {
			t.Fatal("not on curve")
		}
	}
}

func TestIsOnCurveFalse(t *testing.T) {
	P := elliptic.P384().Params().P

	for i := 0; i < 10000; i++ {
		X, _ := rand.Int(rand.Reader, P)
		Y, _ := rand.Int(rand.Reader, P)

		c := &Curve{}
		if c.IsOnCurve(X, Y) {
			t.Fatal("bad point on curve")
		}
	}
}

func TestJacobianAdd(t *testing.T) {
	params := elliptic.P384().Params()

	for i := 0; i < 100; i++ {
		K1, _ := rand.Int(rand.Reader, params.N)
		K2, _ := rand.Int(rand.Reader, params.N)
		X1, Y1 := params.ScalarBaseMult(K1.Bytes())
		X2, Y2 := params.ScalarBaseMult(K2.Bytes())
		X3, Y3 := params.Add(X1, Y1, X2, Y2)

		c := &Curve{}
		in1, in2 := newAffinePoint(X1, Y1), newAffinePoint(X2, Y2)
		pt := c.add(in1.ToJacobian(), in2)
		candX, candY := pt.ToAffine().ToInt()

		if X3.Cmp(candX) != 0 || Y3.Cmp(candY) != 0 {
			t.Fatal("points not the same!")
		}
	}
}

func TestJacobianAddSame(t *testing.T) {
	params := elliptic.P384().Params()

	for i := 0; i < 100; i++ {
		K, _ := rand.Int(rand.Reader, params.N)
		X1, Y1 := params.ScalarBaseMult(K.Bytes())
		X3, Y3 := params.Add(X1, Y1, X1, Y1)

		c := &Curve{}
		in1, in2 := newAffinePoint(X1, Y1), newAffinePoint(X1, Y1)
		pt := c.add(in1.ToJacobian(), in2)
		candX, candY := pt.ToAffine().ToInt()

		if X3.Cmp(candX) != 0 || Y3.Cmp(candY) != 0 {
			t.Fatal("points not the same!")
		}
	}
}

func TestJacobianDouble(t *testing.T) {
	params := elliptic.P384().Params()

	for i := 0; i < 100; i++ {
		K, _ := rand.Int(rand.Reader, params.N)
		X1, Y1 := params.ScalarBaseMult(K.Bytes())
		X3, Y3 := params.Double(X1, Y1)
		X3, Y3 = params.Double(X3, Y3)

		c := &Curve{}
		in := newAffinePoint(X1, Y1)
		pt := c.double(in.ToJacobian())
		pt = c.double(pt)
		candX, candY := pt.ToAffine().ToInt()

		if X3.Cmp(candX) != 0 || Y3.Cmp(candY) != 0 {
			t.Fatal("points not the same!")
		}
	}
}

func TestScalarMult(t *testing.T) {
	params := elliptic.P384().Params()

	for i := 0; i < 100; i++ {
		K, _ := rand.Int(rand.Reader, params.N)
		X, Y := params.ScalarBaseMult(K.Bytes())

		c := &Curve{}
		candX, candY := c.ScalarMult(params.Gx, params.Gy, K.Bytes())

		if X.Cmp(candX) != 0 || Y.Cmp(candY) != 0 {
			t.Fatal("points not the same!")
		}
	}
}

func TestScalarBaseMult(t *testing.T) {
	for i := 0; i < 100; i++ {
		K := make([]byte, 100)
		rand.Read(K)

		X, Y := elliptic.P384().Params().ScalarBaseMult(K)

		c := &Curve{}
		candX, candY := c.ScalarBaseMult(K)

		if X.Cmp(candX) != 0 || Y.Cmp(candY) != 0 {
			t.Fatal("points not the same!")
		}
	}
}

func TestCombinedMult(t *testing.T) {
	params := elliptic.P384().Params()
	K, _ := rand.Int(rand.Reader, params.N)
	X, Y := params.ScalarBaseMult(K.Bytes())

	for i := 0; i < 100; i++ {
		K1, _ := rand.Int(rand.Reader, params.N)
		K2, _ := rand.Int(rand.Reader, params.N)
		X1, Y1 := params.ScalarBaseMult(K1.Bytes())
		X2, Y2 := params.ScalarMult(X, Y, K2.Bytes())
		X3, Y3 := params.Add(X1, Y1, X2, Y2)

		c := &Curve{}
		candX, candY := c.CombinedMult(X, Y, K1.Bytes(), K2.Bytes())

		if X3.Cmp(candX) != 0 || Y3.Cmp(candY) != 0 {
			t.Fatal("points not the same!")
		}
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
	params := elliptic.P384().Params()
	K, _ := rand.Int(rand.Reader, params.N)
	c := &Curve{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.ScalarMult(params.Gx, params.Gy, K.Bytes())
	}
}

func BenchmarkScalarBaseMult(b *testing.B) {
	params := elliptic.P384().Params()
	K, _ := rand.Int(rand.Reader, params.N)
	c := &Curve{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.ScalarBaseMult(K.Bytes())
	}
}

func BenchmarkCombinedMult(b *testing.B) {
	params := elliptic.P384().Params()
	K1, _ := rand.Int(rand.Reader, params.N)
	K2, _ := rand.Int(rand.Reader, params.N)
	c := &Curve{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.CombinedMult(params.Gx, params.Gy, K1.Bytes(), K2.Bytes())
	}
}
