// +build !noasm,arm64 !noasm,amd64

package p384

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func TestInternals(t *testing.T) {
	t.Run("absolute", func(t *testing.T) {
		cases := []int32{-2, -1, 0, 1, 2}
		expected := []int32{2, 1, 0, 1, 2}
		for i := range cases {
			got := absolute(cases[i])
			want := expected[i]
			if got != want {
				test.ReportError(t, got, want, cases[i])
			}
		}
	})

	t.Run("toOdd", func(t *testing.T) {
		var c curve
		k := []byte{0xF0}
		oddK, _ := c.toOdd(k)
		got := len(oddK)
		want := 48
		if got != want {
			test.ReportError(t, got, want)
		}

		oddK[sizeFp-1] = 0x0
		smallOddK, _ := c.toOdd(oddK)
		got = len(smallOddK)
		want = 48
		if got != want {
			test.ReportError(t, got, want)
		}
	})

	t.Run("special k", func(t *testing.T) {
		cases := []struct { // known cases that require complete addition
			w uint
			k int
		}{
			{w: 2, k: 2},
			{w: 5, k: 6},
			{w: 6, k: 38},
			{w: 7, k: 102},
			{w: 9, k: 230},
			{w: 12, k: 742},
			{w: 14, k: 4838},
			{w: 17, k: 21222},
			{w: 19, k: 152294},
		}

		var c curve

		StdCurve := elliptic.P384()
		params := StdCurve.Params()
		for _, caseI := range cases {
			k := big.NewInt(int64(caseI.k)).Bytes()
			gotX, gotY := c.scalarMultOmega(params.Gx, params.Gy, k, caseI.w)
			wantX, wantY := StdCurve.ScalarMult(params.Gx, params.Gy, k)

			if gotX.Cmp(wantX) != 0 {
				test.ReportError(t, gotX, wantX, caseI)
			}
			if gotY.Cmp(wantY) != 0 {
				test.ReportError(t, gotY, wantY, caseI)
			}
		}
	})
}
