package p384

import (
	"testing"

	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

func TestNegZero(t *testing.T) {
	zero, x := &fp384{}, &fp384{}
	fp384Neg(x, zero)

	if *x != *zero {
		t.Errorf("-%v should be %v, not %v", zero, zero, x)
		t.Fatal()
	}
}

func TestNeg(t *testing.T) {
	P := elliptic.P384().Params().P

	for i := 0; i < 20000; i++ {
		x, _ := rand.Int(rand.Reader, P)
		X, Z, Zc := &fp384{}, &fp384{}, &fp384{}
		copy(X[:], x.Bits())

		x.Neg(x).Mod(x, P)
		copy(Zc[:], x.Bits())
		fp384Neg(Z, X)

		if x.Cmp(Z.Int()) != 0 {
			t.Errorf("-%v should be %v, not %v", X, Zc, Z)
			t.Fatal("not equal")
		}
	}
}

func TestAdd(t *testing.T) {
	P := elliptic.P384().Params().P

	for i := 0; i < 10000; i++ {
		x, _ := rand.Int(rand.Reader, P)
		y, _ := rand.Int(rand.Reader, P)
		X, Y, Z, Zc := &fp384{}, &fp384{}, &fp384{}, &fp384{}
		copy(X[:], x.Bits())
		copy(Y[:], y.Bits())

		x.Add(x, y).Mod(x, P)
		copy(Zc[:], x.Bits())
		fp384Add(Z, X, Y)

		if x.Cmp(Z.Int()) != 0 {
			t.Errorf("%v + %v should be %v, not %v", X, Y, Zc, Z)
			t.Fatal()
		}
	}
}

func TestSub(t *testing.T) {
	P := elliptic.P384().Params().P

	for i := 0; i < 10000; i++ {
		x, _ := rand.Int(rand.Reader, P)
		y, _ := rand.Int(rand.Reader, P)
		X, Y, Z, Zc := &fp384{}, &fp384{}, &fp384{}, &fp384{}
		copy(X[:], x.Bits())
		copy(Y[:], y.Bits())

		x.Sub(x, y).Mod(x, P)
		copy(Zc[:], x.Bits())
		fp384Sub(Z, X, Y)

		if x.Cmp(Z.Int()) != 0 {
			t.Errorf("%v - %v should be %v, not %v", X, Y, Zc, Z)
			t.Fatal("not equal")
		}
	}
}

func TestMulZero(t *testing.T) {
	P := elliptic.P384().Params().P
	x, _ := rand.Int(rand.Reader, P)
	X := &fp384{}
	copy(X[:], x.Bits())

	zero := &fp384{}
	fp384Mul(X, X, zero)

	if *X != *zero {
		t.Errorf("%v * %v should be %v, not %v", zero, zero, zero, X)
		t.Fatal("not zero")
	}
}

func TestMul(t *testing.T) {
	P := elliptic.P384().Params().P
	Rinv := big.NewInt(1)
	Rinv.Lsh(Rinv, 384).Mod(Rinv, P).ModInverse(Rinv, P)

	for i := 0; i < 10000; i++ {
		x, _ := rand.Int(rand.Reader, P)
		y, _ := rand.Int(rand.Reader, P)
		X, Y, Z, Zc := &fp384{}, &fp384{}, &fp384{}, &fp384{}
		copy(X[:], x.Bits())
		copy(Y[:], y.Bits())

		x.Mul(x, y).Mul(x, Rinv).Mod(x, P)
		copy(Zc[:], x.Bits())
		fp384Mul(Z, X, Y)

		if x.Cmp(Z.Int()) != 0 {
			t.Errorf("%v * %v should be %v, not %v", X, Y, Zc, Z)
			t.Fatal("not equal")
		}
	}
}

func TestInvert(t *testing.T) {
	P := elliptic.P384().Params().P

	for i := 0; i < 1000; i++ {
		x, _ := rand.Int(rand.Reader, P)
		X, Z, Zc := &fp384{}, &fp384{}, &fp384{}
		copy(X[:], x.Bits())

		x.ModInverse(x, P)
		copy(Zc[:], x.Bits())
		montEncode(Z, X)
		Z.Invert(Z)
		montDecode(Z, Z)

		if x.Cmp(Z.Int()) != 0 {
			t.Errorf("%v^-1 should be %v, not %v", X, Zc, Z)
			t.Fatal("not equal")
		}
	}
}

func BenchmarkMul(b *testing.B) {
	c := elliptic.P384()
	params := c.Params()
	x, _ := rand.Int(rand.Reader, params.P)
	y, _ := rand.Int(rand.Reader, params.P)
	X, Y, Z := &fp384{}, &fp384{}, &fp384{}
	copy(X[:], x.Bits())
	copy(Y[:], y.Bits())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp384Mul(Z, X, Y)
	}
}
