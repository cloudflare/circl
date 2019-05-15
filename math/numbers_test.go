package math

import (
	"math/big"
	"testing"

	"github.com/cloudflare/circl/utils/test"
)

func TestAbsoute(t *testing.T) {
	for _, x := range []int32{-2, -1, 0, 1, 2} {
		y := Absolute(x)
		got := big.NewInt(int64(y))
		want := big.NewInt(int64(x))
		want.Abs(want)

		test.CheckError(t, got, want, x)
	}
}
