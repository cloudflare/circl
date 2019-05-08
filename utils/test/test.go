package test

import (
	"fmt"
	"math/big"
	"testing"
)

// ReportError reports an error if the `got` value is different from `want` value.
func ReportError(t *testing.T, got, want interface{}, inputs ...interface{}) {
	var cmp bool
	bigGot, okGot := got.(*big.Int)
	bigWant, okWant := want.(*big.Int)
	if okGot && okWant {
		cmp = bigGot.Cmp(bigWant) != 0
		got = bigGot.Text(16)
		want = bigWant.Text(16)
	} else {
		cmp = got != want
	}

	if cmp {
		str := "\n"
		for i, in := range inputs {
			str += fmt.Sprintf("in[%v]: %v\n", i, in)
		}
		str += fmt.Sprintf("got: %v\nwant: %v", got, want)
		t.Fatalf(str)
	}
}
