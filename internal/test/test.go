package test

import (
	"fmt"
	"strings"
	"testing"
)

// ReportError reports an error if got is different from want.
func ReportError(t *testing.T, got, want interface{}, inputs ...interface{}) {
	b := &strings.Builder{}
	fmt.Fprint(b, "\n")
	for i, in := range inputs {
		fmt.Fprintf(b, "in[%v]: %v\n", i, in)
	}
	fmt.Fprintf(b, "got:  %v\nwant: %v", got, want)
	t.Helper()
	t.Fatalf(b.String())
}
