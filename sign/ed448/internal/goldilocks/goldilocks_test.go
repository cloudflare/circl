package goldilocks

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/ted448"
	"github.com/cloudflare/circl/internal/test"
	fp "github.com/cloudflare/circl/math/fp448"
)

func randomTwistPoint() ted448.Point {
	var k ted448.Scalar
	_, _ = rand.Read(k[:])
	var P ted448.Point
	ted448.ScalarBaseMult(&P, &k)
	return P
}

func TestIsogeny(t *testing.T) {
	const testTimes = 1 << 10
	var phiP Point
	var Q ted448.Point
	for i := 0; i < testTimes; i++ {
		P := randomTwistPoint()
		R := P
		push(&phiP, &P)
		pull(&Q, &phiP)
		R.Double() // 2P
		R.Double() // 4P
		got := Q
		want := R
		if !got.IsEqual(&want) {
			test.ReportError(t, got, want, P)
		}
	}
}

func TestScalarMult(t *testing.T) {
	const testTimes = 1 << 10
	k := &Scalar{}
	zero := &Scalar{}
	var P, Q, I Point
	var got, want [EncodingSize]byte
	_I := ted448.Identity()
	push(&I, &_I)
	for i := 0; i < testTimes; i++ {
		_, _ = rand.Read(k[:])

		P.ScalarBaseMult(k)
		Q.CombinedMult(k, zero, &I) // k*G + 0*I
		err0 := P.Encode(&got)
		err1 := Q.Encode(&want)
		if err0 != nil || err1 != nil || got != want {
			test.ReportError(t, got, want, k)
		}
	}
}

func TestPointEncoding(t *testing.T) {
	const testTimes = 1 << 10
	var want, got [EncodingSize]byte
	var P Point
	for i := 0; i < testTimes; i++ {
		for found := false; !found; {
			_, _ = rand.Read(want[:])
			want[EncodingSize-1] &= 0x80
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

	var byteDirty, bigY, wrongSignX, nonQR [EncodingSize]byte
	byteDirty[EncodingSize-1] = 0x33
	copy(bigY[:], p[:])
	copy(wrongSignX[:], one[:])
	wrongSignX[EncodingSize-1] = 1 << 7
	nonQR[0] = 2 // smallest y such that (y^2+a)/(dy^2-a) is not a square.

	badEncodings := []*[EncodingSize]byte{
		&byteDirty,  // the last byte is not {0x00,0x80}.
		&bigY,       // y is out of the interval [0,p-1].
		&wrongSignX, // x has wrong sign.
		&nonQR,      // y=2 and (y^2+a)/(dy^2-a) is not a square.
	}

	var P Point
	for _, enc := range badEncodings {
		got := P.Decode(enc)
		want := ErrInvalidDecoding
		if got != want {
			test.ReportError(t, got, want, enc)
		}
	}
}

func BenchmarkEncoding(b *testing.B) {
	var data [EncodingSize]byte
	var k Scalar
	_, _ = rand.Read(k[:])
	var P Point
	P.ScalarBaseMult(&k)
	b.Run("Marshal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = P.Encode(&data)
		}
	})
	b.Run("Unmarshal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = P.Decode(&data)
		}
	})
}
