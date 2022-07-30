package goldilocks_test

import (
	"crypto/rand"
	"errors"
	"testing"

	goldilocks "github.com/cloudflare/circl/ecc/goldilocks"
	ted "github.com/cloudflare/circl/ecc/goldilocks/internal/ted448"
	"github.com/cloudflare/circl/internal/test"
	fp "github.com/cloudflare/circl/math/fp448"
)

func rndScalar(t testing.TB) *goldilocks.Scalar {
	var buf [ted.ScalarSize]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	var s goldilocks.Scalar
	s.FromBytesLE(buf[:])
	return &s
}

func randomPoint(t testing.TB) (P goldilocks.Point) {
	P.ScalarBaseMult(rndScalar(t))
	return P
}

func TestPointAdd(t *testing.T) {
	const testTimes = 1 << 10

	t.Run("P+0=P", func(t *testing.T) {
		I := goldilocks.Identity()
		for i := 0; i < testTimes; i++ {
			P := randomPoint(t)
			got := P
			got.Add(&I)
			want := P
			if got.IsEqual(&want) == 0 {
				test.ReportError(t, got, want, P)
			}
		}
	})

	t.Run("P+(-P)=0", func(t *testing.T) {
		for i := 0; i < testTimes; i++ {
			P := randomPoint(t)
			got := P
			got.Neg()
			got.Add(&P)
			want := goldilocks.Identity()
			if got.IsEqual(&want) == 0 {
				test.ReportError(t, got, want, P)
			}
		}
	})

	t.Run("16P", func(t *testing.T) {
		for i := 0; i < testTimes; i++ {
			P := randomPoint(t)
			// 16P = P+P+...
			R := goldilocks.Identity()
			for i := 0; i < 16; i++ {
				R.Add(&P)
			}
			got := R
			// 16P = 2*2*2*2*P
			P.Double()
			P.Double()
			P.Double()
			P.Double()
			want := P
			if got.IsEqual(&want) == 0 {
				test.ReportError(t, got, want, P)
			}
		}
	})
}

func TestScalarBaseMult(t *testing.T) {
	const testTimes = 1 << 10
	var got, want goldilocks.Point
	G := goldilocks.Generator()
	for i := 0; i < testTimes; i++ {
		k := rndScalar(t)
		got.ScalarBaseMult(k)
		want.ScalarMult(k, &G)
		if got.IsEqual(&want) == 0 {
			test.ReportError(t, got, want, k)
		}
	}
}

func TestScalarMult(t *testing.T) {
	const testTimes = 1 << 9
	zero := &goldilocks.Scalar{}
	var got, want goldilocks.Point
	for i := 0; i < testTimes; i++ {
		k := rndScalar(t)
		Q := randomPoint(t)
		got.ScalarMult(k, &Q)
		want.CombinedMult(zero, k, &Q) // 0*G + k*Q
		if got.IsEqual(&want) == 0 {
			test.ReportError(t, got, want, k)
		}
	}
}

func TestCombinedMult(t *testing.T) {
	const testTimes = 1 << 9
	var got, want, R goldilocks.Point
	for i := 0; i < testTimes; i++ {
		k1 := rndScalar(t)
		k2 := rndScalar(t)
		Q := randomPoint(t)
		got.CombinedMult(k1, k2, &Q) // k1*G + k2*Q

		R.ScalarBaseMult(k1)
		want.ScalarMult(k2, &Q)
		want.Add(&R)

		if got.IsEqual(&want) == 0 {
			test.ReportError(t, got, want, k1, k2, Q)
		}
	}
}

func TestPointEncoding(t *testing.T) {
	const testTimes = 1 << 10
	var want, got [goldilocks.EncodingSize]byte
	var P goldilocks.Point
	for i := 0; i < testTimes; i++ {
		for found := false; !found; {
			_, _ = rand.Read(want[:])
			want[goldilocks.EncodingSize-1] &= 0x80
			err := P.Decode(&want)
			found = err == nil
		}
		err := P.Encode(&got)
		if err != nil || got != want {
			test.ReportError(t, got, want, P)
		}
	}
}

func TestPointInvalid(t *testing.T) {
	p := fp.P()
	one := fp.One()

	var byteDirty, bigY, wrongSignX, nonQR [goldilocks.EncodingSize]byte
	byteDirty[goldilocks.EncodingSize-1] = 0x33
	copy(bigY[:], p[:])
	copy(wrongSignX[:], one[:])
	wrongSignX[goldilocks.EncodingSize-1] = 1 << 7
	nonQR[0] = 2 // smallest y such that (y^2+a)/(dy^2-a) is not a square.

	badEncodings := []*[goldilocks.EncodingSize]byte{
		&byteDirty,  // the last byte is not {0x00,0x80}.
		&bigY,       // y is out of the interval [0,p-1].
		&wrongSignX, // x has wrong sign.
		&nonQR,      // y=2 and (y^2+a)/(dy^2-a) is not a square.
	}

	var P goldilocks.Point
	for _, enc := range badEncodings {
		got := P.Decode(enc)
		want := goldilocks.ErrInvalidDecoding
		if !errors.Is(got, want) {
			test.ReportError(t, got, want, enc)
		}
	}
}

func BenchmarkPoint(b *testing.B) {
	k := rndScalar(b)
	l := rndScalar(b)
	P := randomPoint(b)
	Q := randomPoint(b)

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.Add(&Q)
		}
	})
	b.Run("Double", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.Double()
		}
	})
	b.Run("ScalarMult", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Q.ScalarMult(k, &P)
		}
	})
	b.Run("ScalarBaseMult", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.ScalarBaseMult(k)
		}
	})
	b.Run("CombinedMult", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Q.CombinedMult(k, l, &P)
		}
	})
}

func BenchmarkScalar(b *testing.B) {
	x := rndScalar(b)
	y := rndScalar(b)
	z := rndScalar(b)

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Add(x, y)
		}
	})
	b.Run("Sub", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Sub(x, y)
		}
	})
	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Mul(x, y)
		}
	})
	b.Run("Inv", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Inv(x)
		}
	})
}

func BenchmarkEncoding(b *testing.B) {
	var data [goldilocks.EncodingSize]byte
	k := rndScalar(b)
	var P goldilocks.Point
	P.ScalarBaseMult(k)
	b.Run("Encode", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = P.Encode(&data)
		}
	})
	b.Run("Decode", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = P.Decode(&data)
		}
	})
}
