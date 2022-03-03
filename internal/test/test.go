package test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// ReportError reports an error if got is different from want.
func ReportError(t testing.TB, got, want interface{}, inputs ...interface{}) {
	b := &strings.Builder{}
	fmt.Fprint(b, "\n")
	for i, in := range inputs {
		fmt.Fprintf(b, "in[%v]: %v\n", i, in)
	}
	fmt.Fprintf(b, "got:  %v\nwant: %v", got, want)
	t.Helper()
	t.Fatalf(b.String())
}

// CheckOk fails the test if result == false.
func CheckOk(result bool, msg string, t testing.TB) {
	t.Helper()

	if !result {
		t.Fatal(msg)
	}
}

// checkErr fails on error condition. mustFail indicates whether err is expected
// to be nil or not.
func checkErr(t testing.TB, err error, mustFail bool, msg string) {
	t.Helper()
	if err != nil && !mustFail {
		t.Fatalf("msg: %v\nerr: %v", msg, err)
	}

	if err == nil && mustFail {
		t.Fatalf("msg: %v\nerr: %v", msg, err)
	}
}

// CheckNoErr fails if err !=nil. Print msg as an error message.
func CheckNoErr(t testing.TB, err error, msg string) { t.Helper(); checkErr(t, err, false, msg) }

// CheckIsErr fails if err ==nil. Print msg as an error message.
func CheckIsErr(t testing.TB, err error, msg string) { t.Helper(); checkErr(t, err, true, msg) }

// CheckPanic returns true if call to function 'f' caused panic.
func CheckPanic(f func()) error {
	hasPanicked := errors.New("no panic detected")
	defer func() {
		if r := recover(); r != nil {
			hasPanicked = nil
		}
	}()
	f()
	return hasPanicked
}
