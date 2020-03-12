package fourq

import (
	"crypto/rand"
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
