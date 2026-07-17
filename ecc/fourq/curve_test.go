package fourq

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/internal/test"
)

func (P *Point) random() {
	var _P pointR1
	_P.random()
	P.fromR1(&_P)
}

func TestMarshal(t *testing.T) {
	testTimes := 1 << 10
	var buf, k [Size]byte
	var P, Q, R Point
	t.Run("k*um(P)=kP", func(t *testing.T) {
		for i := 0; i < testTimes; i++ {
			P.random()
			_, _ = rand.Read(k[:])

			P.Marshal(&buf)
			if ok := Q.Unmarshal(&buf); !ok {
				test.ReportError(t, ok, true)
			}
			Q.ScalarMult(&k, &Q)
			R.ScalarMult(&k, &P)

			got := Q.X
			want := R.X
			if got != want {
				test.ReportError(t, got, want, P, k)
			}
			got = Q.Y
			want = R.Y
			if got != want {
				test.ReportError(t, got, want, P, k)
			}
		}
	})
	t.Run("m(kP)~=m(-kP)", func(t *testing.T) {
		c := Params()
		var minusK, encQ, encR [Size]byte
		for i := 0; i < testTimes; i++ {
			P.random()
			bigK, _ := rand.Int(rand.Reader, c.N)
			conv.BigInt2BytesLe(k[:], bigK)
			bigK.Neg(bigK).Mod(bigK, c.N)
			conv.BigInt2BytesLe(minusK[:], bigK)
			Q.ScalarMult(&k, &P)
			R.ScalarMult(&minusK, &P)
			Q.Marshal(&encQ)
			R.Marshal(&encR)

			got := encQ[31] >> 7
			want := 1 - (encR[31] >> 7)
			encQ[31] &= 0x7F
			encR[31] &= 0x7F

			if encQ != encR {
				test.ReportError(t, encQ, encR, P, k)
			}
			if got != want {
				test.ReportError(t, got, want, P, k)
			}
		}
	})
}

func BenchmarkCurve(b *testing.B) {
	var P, Q, R Point
	var k [32]byte

	_, _ = rand.Read(k[:])
	P.ScalarBaseMult(&k)
	_, _ = rand.Read(k[:])
	Q.ScalarBaseMult(&k)
	_, _ = rand.Read(k[:])
	R.ScalarBaseMult(&k)

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.Add(&Q, &R)
		}
	})

	b.Run("Double", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.Add(&Q, &Q)
		}
	})

	b.Run("ScalarBaseMult", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.ScalarBaseMult(&k)
		}
	})

	b.Run("ScalarMult", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.ScalarMult(&k, &Q)
		}
	})
}

func TestFqSqrBorrowBug(t *testing.T) {
	P := getModulus()
	x, gotAsm, gotGen := &Fq{}, &Fq{}, &Fq{}

	bigX0 := big.NewInt(0)                       // a0 = 0
	bigX1 := new(big.Int).Lsh(big.NewInt(1), 64) // a1 = 2^64  (canonical, < p), so a0_lo == a1_lo and a0 < a1

	x.setBigInt(bigX0, bigX1)
	fqSqr(gotAsm, x)        // dispatched implementation (BMI2 asm on default amd64 build)
	fqSqrGeneric(gotGen, x) // portable reference

	// want = x^2 over GF(p^2): re = x0^2 - x1^2, im = 2*x0*x1 (mod p)
	x0x0 := new(big.Int).Mul(bigX0, bigX0)
	x0x1 := new(big.Int).Mul(bigX0, bigX1)
	x1x1 := new(big.Int).Mul(bigX1, bigX1)
	want0 := new(big.Int).Mod(new(big.Int).Sub(x0x0, x1x1), P)
	want1 := new(big.Int).Mod(new(big.Int).Lsh(x0x1, 1), P)

	g0, g1 := gotGen.toBigInt()
	if g0.Cmp(want0) != 0 || g1.Cmp(want1) != 0 {
		t.Fatalf("generic fqSqr disagrees with math/big:\n got (%v, %v)\nwant (%v, %v)", g0, g1, want0, want1)
	}
	a0, a1 := gotAsm.toBigInt()
	if a0.Cmp(want0) != 0 || a1.Cmp(want1) != 0 {
		t.Fatalf("fqSqr disagrees with math/big and the generic implementation:\n got (%v, %v)\nwant (%v, %v)", a0, a1, want0, want1)
	}
}

func TestUnmarshalBorrowBug(t *testing.T) {
	var in [Size]byte
	var P Point
	accepted := []uint64{}
	for j := uint64(1); j <= 64; j++ {
		for i := range in {
			in[i] = 0
		}
		// bytes [0:16]  = y[0] = 0
		// bytes [16:32] = y[1] = j * 2^64  (little endian) -> y0_lo == y1_lo, y0 < y1
		binary.LittleEndian.PutUint64(in[24:32], j)
		if P.Unmarshal(&in) {
			accepted = append(accepted, j)
		}
	}
	// purego/reference build accepts 29 keys: [1 2 8 10 13 15 17 22 23 25 26 28 30 33 35 38 39 41 42 46 47 48 49 52 53 54 56 58 62]
	// default amd64 (BMI2) build accepts 0.
	t.Logf("accepted %d of 64 candidate keys: %v", len(accepted), accepted)
}
