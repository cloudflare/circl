package test

import (
	"bytes"
	"compress/gzip"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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
	t.Fatal(b.String())
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

func CheckMarshal(
	t *testing.T,
	x, y interface {
		encoding.BinaryMarshaler
		encoding.BinaryUnmarshaler
	},
) {
	t.Helper()

	want, err := x.MarshalBinary()
	CheckNoErr(t, err, fmt.Sprintf("cannot marshal %T = %v", x, x))

	err = y.UnmarshalBinary(want)
	CheckNoErr(t, err, fmt.Sprintf("cannot unmarshal %T from %x", y, want))

	got, err := y.MarshalBinary()
	CheckNoErr(t, err, fmt.Sprintf("cannot marshal %T = %v", y, y))

	if !bytes.Equal(got, want) {
		ReportError(t, got, want, x, y)
	}
}

// []byte but is encoded in hex for JSON
type HexBytes []byte

func (b HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(b))
}

func (b *HexBytes) UnmarshalJSON(data []byte) (err error) {
	var s string
	if err = json.Unmarshal(data, &s); err != nil {
		return err
	}
	*b, err = hex.DecodeString(strings.TrimPrefix(s, "0x"))
	return err
}

func gunzip(in []byte) ([]byte, error) {
	buf := bytes.NewBuffer(in)
	r, err := gzip.NewReader(buf)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// Like os.ReadFile, but gunzip first.
func ReadGzip(path string) ([]byte, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return gunzip(buf)
}
