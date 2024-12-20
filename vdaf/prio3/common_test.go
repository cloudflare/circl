package prio3

import (
	"bytes"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"testing"

	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/vdaf/prio3/internal/prio3"
	"golang.org/x/crypto/cryptobyte"
)

type marshaler interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

func testMarshal[T any](t testing.TB, x *T, p *prio3.Params, extra ...uint) {
	t.Helper()
	bm := any(x).(marshaler)
	b0, err := bm.MarshalBinary()
	test.CheckNoErr(t, err, "first MarshalBinary failed")

	y := new(T)
	yy, ok := any(y).(interface{ New(*prio3.Params) *T })
	if ok {
		yy.New(p)
	} else {
		yy, ok := any(y).(interface{ New(*prio3.Params, uint) *T })
		if ok {
			yy.New(p, extra[0])
		}
	}

	bm = any(y).(marshaler)
	err = bm.UnmarshalBinary(b0)
	test.CheckNoErr(t, err, "UnmarshalBinary failed")

	b1, err := bm.MarshalBinary()
	test.CheckNoErr(t, err, "second MarshalBinary failed")

	if !bytes.Equal(b0, b1) {
		test.ReportError(t, b0, b1)
	}

	// check for invalid size
	err = bm.UnmarshalBinary(nil)
	test.CheckIsErr(t, err, "UnmarshalBinary should failed")
}

func fromReader[T any](t testing.TB, r io.Reader) (z T) {
	var err error
	switch zz := any(&z).(type) {
	case *prio3.Nonce:
		_, err = r.Read(zz[:])
	case *prio3.VerifyKey:
		_, err = r.Read(zz[:])
	default:
		err = errors.New("wrong type")
	}
	test.CheckNoErr(t, err, "fromReader failed")
	return
}

func fromHex[T any](t testing.TB, x Hex) (z T) {
	var err error
	switch zz := any(&z).(type) {
	case *prio3.Nonce:
		copy(zz[:], x[:prio3.NonceSize])
	case *prio3.VerifyKey:
		copy(zz[:], x[:prio3.VerifyKeySize])
	default:
		err = errors.New("wrong type")
	}
	test.CheckNoErr(t, err, "fromHex failed")
	return
}

type Hex []byte

func (b *Hex) UnmarshalJSON(data []byte) (err error) {
	var s string
	if err = json.Unmarshal(data, &s); err != nil {
		return err
	}
	*b, err = hex.DecodeString(s)
	return err
}

func readFile[V any](t *testing.T, fileName string) (v V) {
	t.Helper()
	jsonFile, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", fileName, err)
	}
	defer jsonFile.Close()
	input, err := io.ReadAll(jsonFile)
	if err != nil {
		t.Fatalf("File %v can not be read. Error: %v", fileName, err)
	}

	err = json.Unmarshal(input, &v)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", fileName, err)
	}

	return
}

func checkEqual[T any](t *testing.T, a T, b []byte) {
	t.Helper()
	aa, err := conv.MarshalBinary(any(a).(cryptobyte.MarshalingValue))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(aa, b) {
		test.ReportError(t, hex.EncodeToString(aa), hex.EncodeToString(b))
	}
}

func isEqual[T any](t *testing.T, a, b T) bool {
	switch aa := any(a).(type) {
	case uint64:
		return aa == any(b).(uint64)
	case []uint64:
		return slices.Equal(aa, any(b).([]uint64))
	default:
		t.Fatalf("unrecognized aggregate type: %T\n", a)
		return false
	}
}
