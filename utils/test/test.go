package test

import (
	"fmt"
	"math/big"
	"strings"
	"testing"
)

// CheckError reports an error if got is different from want. The only supported
// types for got and want are basic standard types or *big.Int.
func CheckError(t *testing.T, got, want interface{}, inputs ...interface{}) {
	var cmp bool
	bigGot, okGot := got.(*big.Int)
	bigWant, okWant := want.(*big.Int)
	if okGot && okWant {
		cmp = bigGot.Cmp(bigWant) != 0
		got = "0x" + bigGot.Text(16)
		want = "0x" + bigWant.Text(16)
	} else {
		cmp = got != want
	}

	if cmp {
		b := &strings.Builder{}
		fmt.Fprint(b, "\n")
		for i, in := range inputs {
			fmt.Fprintf(b, "in[%v]: %v\n", i, in)
		}
		fmt.Fprintf(b, "got:  %v\nwant: %v", got, want)
		t.Fatalf(b.String())
	}
}
