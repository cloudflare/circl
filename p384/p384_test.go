package p384

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/cloudflare/circl/utils"
	"github.com/cloudflare/circl/utils/test"
)

func TestIsOnCurveTrue(t *testing.T) {
	for i := 0; i < 100; i++ {
		K := make([]byte, 384/8)
		_, _ = rand.Read(K)

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

func TestAffineAdd(t *testing.T) {
	params := elliptic.P384().Params()

	for i := 0; i < 100; i++ {
		K1, _ := rand.Int(rand.Reader, params.N)
		K2, _ := rand.Int(rand.Reader, params.N)
		X1, Y1 := params.ScalarBaseMult(K1.Bytes())
		X2, Y2 := params.ScalarBaseMult(K2.Bytes())
		X3, Y3 := params.Add(X1, Y1, X2, Y2)

		c := &Curve{}
		candX, candY := c.Add(X1, Y1, X2, Y2)

		if X3.Cmp(candX) != 0 || Y3.Cmp(candY) != 0 {
			t.Fatal("points not the same!")
		}
	}
}

func TestJacobianMixAdd(t *testing.T) {
	params := elliptic.P384().Params()

	for i := 0; i < 100; i++ {
		K1, _ := rand.Int(rand.Reader, params.N)
		K2, _ := rand.Int(rand.Reader, params.N)
		X1, Y1 := params.ScalarBaseMult(K1.Bytes())
		X2, Y2 := params.ScalarBaseMult(K2.Bytes())
		X3, Y3 := params.Add(X1, Y1, X2, Y2)

		c := &Curve{}
		in1, in2 := newAffinePoint(X1, Y1), newAffinePoint(X2, Y2)
		pt := c.mixadd(in1.toJacobian(), in2)
		candX, candY := pt.toAffine().toInt()

		if X3.Cmp(candX) != 0 || Y3.Cmp(candY) != 0 {
			t.Fatal("points not the same!")
		}
	}
}

func TestJacobianMixAddSame(t *testing.T) {
	params := elliptic.P384().Params()

	for i := 0; i < 100; i++ {
		K, _ := rand.Int(rand.Reader, params.N)
		X1, Y1 := params.ScalarBaseMult(K.Bytes())
		X3, Y3 := params.Add(X1, Y1, X1, Y1)

		c := &Curve{}
		in1, in2 := newAffinePoint(X1, Y1), newAffinePoint(X1, Y1)
		pt := c.mixadd(in1.toJacobian(), in2)
		candX, candY := pt.toAffine().toInt()

		if X3.Cmp(candX) != 0 || Y3.Cmp(candY) != 0 {
			t.Fatal("points not the same!")
		}
	}
}

func TestAffineDouble(t *testing.T) {
	params := elliptic.P384().Params()

	for i := 0; i < 100; i++ {
		K, _ := rand.Int(rand.Reader, params.N)
		X1, Y1 := params.ScalarBaseMult(K.Bytes())
		X3, Y3 := params.Double(X1, Y1)
		X3, Y3 = params.Double(X3, Y3)

		c := &Curve{}
		candX, candY := c.Double(X1, Y1)
		candX, candY = c.Double(candX, candY)

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
		pt := c.double(in.toJacobian())
		pt = c.double(pt)
		candX, candY := pt.toAffine().toInt()

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
		_, _ = rand.Read(K)

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

func TestPointAdd(t *testing.T) {
	params := elliptic.P384().Params()
	c := &Curve{}
	Z := c.Zero()

	var R jacobianPoint
	K1, _ := rand.Int(rand.Reader, params.N)
	X1, Y1 := params.ScalarBaseMult(K1.Bytes())
	P := newAffinePoint(X1, Y1).toJacobian()

	// Test O+O = O
	R.add(Z, Z)
	got := R.isZero()
	want := true
	test.ReportError(t, got, want, K1)

	// Test O+P = P
	R.add(P, Z)
	gotX, gotY := R.toAffine().toInt()
	wantX, wantY := P.toAffine().toInt()
	test.ReportError(t, gotX, wantX, K1)
	test.ReportError(t, gotY, wantY)

	// Test P+O = P
	R.add(Z, P)
	gotX, gotY = R.toAffine().toInt()
	wantX, wantY = P.toAffine().toInt()
	test.ReportError(t, gotX, wantX, K1)
	test.ReportError(t, gotY, wantY)

	// Test P+(-P) = O
	Q := *P
	Q.neg()
	R.add(P, &Q)
	got = R.isZero()
	want = true
	test.ReportError(t, got, want, K1)

	// Test P+P = 2P
    ?// TODO
	Q = *P
	R.add(P, P)
	Q.double()
	gotX, gotY = R.toAffine().toInt()
	wantX, wantY = Q.toAffine().toInt()
	test.ReportError(t, gotX, wantX, K1)
	test.ReportError(t, gotY, wantY)

	for i := 0; i < 100; i++ {
		K1, _ := rand.Int(rand.Reader, params.N)
		K2, _ := rand.Int(rand.Reader, params.N)
		X1, Y1 := params.ScalarBaseMult(K1.Bytes())
		X2, Y2 := params.ScalarBaseMult(K2.Bytes())
		wantX, wantY := params.Add(X1, Y1, X2, Y2)

		P := newAffinePoint(X1, Y1).toJacobian()
		Q := newAffinePoint(X2, Y2).toJacobian()
		R.add(P, Q)
		gotX, gotY := R.toAffine().toInt()

		test.ReportError(t, gotX, wantX, K1, K2)
		test.ReportError(t, gotY, wantY)
	}
}
func TestOddMultiples(t *testing.T) {
	params := elliptic.P384().Params()
	var jOdd [4]byte

	for w := uint(0); w < 2; w++ {
		k, _ := rand.Int(rand.Reader, params.N)
		X, Y := params.ScalarBaseMult(k.Bytes())
		P := newAffinePoint(X, Y).toJacobian()
		PP := P.OddMultiples(w)
		got := len(PP)
		want := 0
		test.ReportError(t, got, want, w)
	}

	for w := uint(2); w < 10; w++ {
		for i := 0; i < 32; i++ {
			k, _ := rand.Int(rand.Reader, params.N)
			X, Y := params.ScalarBaseMult(k.Bytes())
			P := newAffinePoint(X, Y).toJacobian()
			PP := P.OddMultiples(w)
			for j, jP := range PP {
				binary.BigEndian.PutUint32(jOdd[:], uint32(2*j+1))
				wantX, wantY := params.ScalarMult(X, Y, jOdd[:])
				gotX, gotY := jP.toAffine().toInt()
				test.ReportError(t, gotX, wantX, w, k, j)
				test.ReportError(t, gotY, wantY)
			}
		}
	}
}
func TestSimultaneous(t *testing.T) {
	params := elliptic.P384().Params()

	for i := 0; i < 100; i++ {
		k := []byte{0xA5, 0x5A, 0xAB, 0x02, 0x1F}

		K, _ := rand.Int(rand.Reader, params.N)
		X, Y := params.ScalarBaseMult(K.Bytes())
		wantX, wantY := params.ScalarMult(X, Y, k)

		var R jacobianPoint
		Q := newAffinePoint(X, Y).toJacobian()
		R.SimultaneousMult(Q, k[:3], k)
		gotX, gotY := R.toAffine().toInt()
		t.Logf("X: %v\n", gotX)
		t.Logf("Y: %v\n", gotY)
		test.ReportError(t, gotX, wantX, K)
		test.ReportError(t, gotY, wantY)
	}
}

func BenchmarkPointAddition(b *testing.B) {
	var P, Q, R jacobianPoint
	utils.NonCryptoRand(P.x[:])
	utils.NonCryptoRand(P.y[:])
	utils.NonCryptoRand(P.z[:])
	utils.NonCryptoRand(Q.x[:])
	utils.NonCryptoRand(Q.y[:])
	utils.NonCryptoRand(Q.z[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		R.add(&P, &Q)
	}
}
func BenchmarkPointMixAdd(b *testing.B) {
	var P jacobianPoint
	var Q affinePoint
	utils.NonCryptoRand(P.x[:])
	utils.NonCryptoRand(P.y[:])
	utils.NonCryptoRand(P.z[:])
	utils.NonCryptoRand(Q.x[:])
	utils.NonCryptoRand(Q.y[:])
	c := &Curve{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.mixadd(&P, &Q)
	}
}
func BenchmarkPointDouble(b *testing.B) {
	var P jacobianPoint
	utils.NonCryptoRand(P.x[:])
	utils.NonCryptoRand(P.y[:])
	utils.NonCryptoRand(P.z[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		P.double()
	}
}
func BenchmarkSimultaneous(b *testing.B) {
	var P, Q jacobianPoint
	utils.NonCryptoRand(Q.x[:])
	utils.NonCryptoRand(Q.y[:])
	utils.NonCryptoRand(Q.z[:])
	params := elliptic.P384().Params()
	K1, _ := rand.Int(rand.Reader, params.N)
	K2, _ := rand.Int(rand.Reader, params.N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		P.SimultaneousMult(&Q, K1.Bytes(), K2.Bytes())
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
