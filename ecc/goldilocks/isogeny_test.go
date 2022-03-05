package goldilocks

import (
	"crypto/rand"
	"testing"

	ted "github.com/cloudflare/circl/ecc/goldilocks/internal/ted448"
	"github.com/cloudflare/circl/internal/test"
)

func rndScalar(t testing.TB) *ted.Scalar {
	var buf [ted.ScalarSize]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	var s ted.Scalar
	s.FromBytesLE(buf[:])
	return &s
}

func randomTwistPoint(t *testing.T) (P ted.Point) {
	ted.ScalarBaseMult(&P, rndScalar(t))
	return P
}

func TestIsogeny(t *testing.T) {
	const testTimes = 1 << 10
	var phiP Point
	var Q ted.Point
	for i := 0; i < testTimes; i++ {
		P := randomTwistPoint(t)
		R := P
		push(&phiP, &P)
		pull(&Q, &phiP)
		R.Double() // 2P
		R.Double() // 4P
		got := Q
		want := R
		if got.IsEqual(&want) == 0 {
			test.ReportError(t, got, want, P)
		}
	}
}
