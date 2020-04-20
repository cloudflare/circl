package bls12381

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func randomFp2() *fp2 {
	var x fp2
	n0, _ := rand.Int(rand.Reader, blsPrime)
	n1, _ := rand.Int(rand.Reader, blsPrime)
	x[0].Int.Set(n0)
	x[1].Int.Set(n1)
	return &x
}

func TestFp2(t *testing.T) {
	const testTimes = 1 << 6
	var z fp2
	for i := 0; i < testTimes; i++ {
		x := randomFp2()
		y := randomFp2()

		// x*y*x^1 - y = 0
		z.Inv(x)
		z.Mul(&z, y)
		z.Mul(&z, x)
		z.Sub(&z, y)
		got := z.IsZero()
		want := true
		if got != want {
			t.Logf("%v %v\n", z, y)
			test.ReportError(t, got, want, x, y)
		}
	}
}
