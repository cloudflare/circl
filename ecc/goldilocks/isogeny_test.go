package goldilocks

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func randomPoint() *Point {
	k := make([]byte, 1)
	_, _ = rand.Read(k[:])
	var e Curve
	P := e.Generator()
	for i := byte(0); i < k[0]; i++ {
		P = e.Double(P)
	}
	return P
}

func TestIsogeny(t *testing.T) {
	const testTimes = 1 << 10
	var gold Curve
	var twist twistCurve

	for i := 0; i < testTimes; i++ {
		P := randomPoint()
		Q := gold.pull(gold.push(P)) // phi^-(phi^+(P))
		got := Q
		want := gold.Double(gold.Double(P)) // 4P
		if !got.IsEqual(want) {
			test.ReportError(t, got, want, P)
		}
		got = twist.push(twist.pull(Q))    // phi^-(phi^+(Q))
		want = gold.Double(gold.Double(Q)) // 4Q
		if !got.IsEqual(want) {
			test.ReportError(t, got, want, P)
		}
	}
}
