package fourq

import (
	"testing"

	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"golang.org/x/crypto/curve25519"
)

func TestIsOnCurve(t *testing.T) {
	if !IsOnCurve(G) {
		t.Fatal("Generator is not on curve.")
	}

	pt2, ok := ScalarMult(G, Order.Bytes(), false)
	if ok {
		t.Fatal("Returned ok on identity point.")
	} else if !IsOnCurve(pt2) {
		t.Fatal("Identity point is not on curve.")
	}

	k := make([]byte, 32)
	rand.Read(k)
	pt3, ok := ScalarMult(G, k, false)
	if !ok {
		t.Fatal("not ok")
	} else if !IsOnCurve(pt3) {
		t.Fatal("Random multiple of generator is not on curve.")
	}

	pt4 := [32]byte{}
	pt4[0], pt4[16] = 5, 7
	if IsOnCurve(pt4) {
		t.Fatal("Non-existent point is on curve.")
	}
}

func TestIsOnCurveU(t *testing.T) {
	if !IsOnCurveU(GU) {
		t.Fatal("Generator is not on curve.")
	}

	pt2, ok := ScalarMultU(GU, Order.Bytes(), false)
	if ok {
		t.Fatal("Returned ok on identity point.")
	} else if !IsOnCurveU(pt2) {
		t.Fatal("Identity point is not on curve.")
	}

	k := make([]byte, 32)
	rand.Read(k)
	pt3, ok := ScalarMultU(GU, k, false)
	if !ok {
		t.Fatal("not ok")
	} else if !IsOnCurveU(pt3) {
		t.Fatal("Random multiple of generator is not on curve.")
	}

	pt4 := [64]byte{}
	pt4[0], pt4[32] = 5, 7
	if IsOnCurveU(pt4) {
		t.Fatal("Non-existent point is on curve.")
	}
}

func TestScalarBaseMult(t *testing.T) {
	pt3, ok := ScalarBaseMult(Order.Bytes())
	if !ok {
		t.Fatal("not ok")
	} else if pt3 != [32]byte{1} {
		t.Fatal("ScalarBaseMult(Order) was not identity.")
	}

	k := make([]byte, 32)
	rand.Read(k)

	pt4, ok := ScalarMult(G, k, false)
	if !ok {
		t.Fatal("not ok")
	}
	pt5, ok := ScalarBaseMult(k)
	if !ok {
		t.Fatal("not ok")
	} else if pt4 != pt5 {
		t.Fatal("ScalarMult(G, k) != ScalarBaseMult(k)")
	}
}

func TestScalarBaseMultU(t *testing.T) {
	pt3, ok := ScalarBaseMultU(Order.Bytes())
	if !ok {
		t.Fatal("not ok")
	} else if pt3 != uncompressedIdentity {
		t.Fatal("ScalarBaseMultU(Order) was not identity.")
	}

	k := make([]byte, 32)
	rand.Read(k)

	pt4, ok := ScalarMultU(GU, k, false)
	if !ok {
		t.Fatal("not ok")
	}
	pt5, ok := ScalarBaseMultU(k)
	if !ok {
		t.Fatal("not ok")
	} else if pt4 != pt5 {
		t.Fatal("ScalarMultU(GU, k) != ScalarBaseMultU(k)")
	}
}

func TestScalarMult(t *testing.T) {
	// Source: https://github.com/bifurcation/fourq/blob/master/impl/curve4q.py#L549
	scalar := [4]uint64{0x3AD457AB55456230, 0x3A8B3C2C6FD86E0C, 0x7E38F7C9CFBB9166, 0x0028FD6CBDA458F0}

	pt := G
	var ok bool
	for i := 0; i < 1000; i++ {
		scalar[1] = scalar[2]
		scalar[2] += scalar[0]
		scalar[2] &= 0xffffffffffffffff

		k := new(big.Int).SetUint64(scalar[3])
		k.Lsh(k, 64)
		k.Add(k, new(big.Int).SetUint64(scalar[2]))
		k.Lsh(k, 64)
		k.Add(k, new(big.Int).SetUint64(scalar[1]))
		k.Lsh(k, 64)
		k.Add(k, new(big.Int).SetUint64(scalar[0]))

		pt, ok = ScalarMult(pt, k.Bytes(), false)
		if !ok {
			t.Fatal("not ok")
		}
	}

	real := "44336f9967501c286c930e7c81b3010945125f9129c4e84f10e2acac8e940b57"
	if fmt.Sprintf("%x", pt) != real {
		t.Fatal("Point is wrong!")
	}
}

func TestScalarMultU(t *testing.T) {
	// Source: https://github.com/bifurcation/fourq/blob/master/impl/curve4q.py#L549
	scalar := [4]uint64{0x3AD457AB55456230, 0x3A8B3C2C6FD86E0C, 0x7E38F7C9CFBB9166, 0x0028FD6CBDA458F0}

	pt := GU
	var ok bool
	for i := 0; i < 1000; i++ {
		scalar[1] = scalar[2]
		scalar[2] += scalar[0]
		scalar[2] &= 0xffffffffffffffff

		k := new(big.Int).SetUint64(scalar[3])
		k.Lsh(k, 64)
		k.Add(k, new(big.Int).SetUint64(scalar[2]))
		k.Lsh(k, 64)
		k.Add(k, new(big.Int).SetUint64(scalar[1]))
		k.Lsh(k, 64)
		k.Add(k, new(big.Int).SetUint64(scalar[0]))

		pt, ok = ScalarMultU(pt, k.Bytes(), false)
		if !ok {
			t.Fatal("not ok")
		}
	}

	real := "ef4b49bd77b4d2df1b4ac9bf2b127c2559c4377254939576011fb1b50cf89b4644336f9967501c286c930e7c81b3010945125f9129c4e84f10e2acac8e940b57"
	if fmt.Sprintf("%x", pt) != real {
		t.Fatal("Point is wrong!")
	}
}

func TestCofactorClearing(t *testing.T) {
	limit := big.NewInt(1)
	limit.Lsh(limit, 200)

	K1, _ := rand.Int(rand.Reader, limit)
	K2 := big.NewInt(392)
	K2.Mul(K1, K2)

	pt1, ok := ScalarMult(G, K1.Bytes(), true)
	if !ok {
		t.Fatal("not ok")
	}
	pt2, ok := ScalarMult(G, K2.Bytes(), false)
	if !ok {
		t.Fatal("not ok")
	}

	if pt1 != pt2 {
		t.Fatal("Points are not the same.")
	}
}

func BenchmarkScalarBaseMult(b *testing.B) {
	k := make([]byte, 32)
	rand.Read(k)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ScalarBaseMult(k)
	}
}

func BenchmarkScalarMult(b *testing.B) {
	k := make([]byte, 32)
	rand.Read(k)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ScalarMult(G, k, false)
	}
}

func BenchmarkScalarMultU(b *testing.B) {
	k := make([]byte, 32)
	rand.Read(k)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ScalarMultU(GU, k, false)
	}
}

func BenchmarkP256Base(b *testing.B) {
	c := elliptic.P256()

	k := make([]byte, 32)
	rand.Read(k)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.ScalarBaseMult(k)
	}
}

func BenchmarkP256(b *testing.B) {
	c := elliptic.P256()
	params := c.Params()

	k := make([]byte, 32)
	rand.Read(k)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.ScalarMult(params.Gx, params.Gy, k)
	}
}

func BenchmarkCurve25519(b *testing.B) {
	dst, in := [32]byte{}, [32]byte{}
	rand.Read(in[:])

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		curve25519.ScalarBaseMult(&dst, &in)
	}
}
