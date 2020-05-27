package goldilocks

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func randomPoint() *Point {
	var k Scalar
	_, _ = rand.Read(k[:])
	return Curve{}.ScalarBaseMult(&k)
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
