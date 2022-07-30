package group

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	fp "github.com/cloudflare/circl/math/fp448"
)

type testJSONFile struct {
	Multiples []string `json:"multiples"`
	Invalid   []struct {
		Description string   `json:"description"`
		Encodings   []string `json:"encodings"`
	} `json:"invalid"`
	Oneway []struct {
		Input  string `json:"input"`
		Output string `json:"output"`
	} `json:"oneway"`
}

func (kat *testJSONFile) readFile(t *testing.T, fileName string) {
	jsonFile, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", fileName, err)
	}
	defer jsonFile.Close()
	input, _ := ioutil.ReadAll(jsonFile)

	err = json.Unmarshal(input, &kat)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", fileName, err)
	}
}

func (kat *testJSONFile) multiples(t *testing.T) {
	k := Decaf448.NewScalar()
	got := Decaf448.NewElement()
	want := Decaf448.NewElement()

	for i, vi := range kat.Multiples {
		k.SetUint64(uint64(i))
		got.MulGen(k)
		gotEnc, err := got.MarshalBinary()
		test.CheckNoErr(t, err, "marshaling element")

		wantEnc, err := hex.DecodeString(vi)
		test.CheckNoErr(t, err, "bad hex encoding")
		err = want.UnmarshalBinary(wantEnc)
		test.CheckNoErr(t, err, "bad element unmarshaling")

		if !got.IsEqual(want) {
			test.ReportError(t, got, want, i)
		}

		if !bytes.Equal(gotEnc, wantEnc) {
			test.ReportError(t, gotEnc, wantEnc, i)
		}
	}
}

func (kat *testJSONFile) invalid(t *testing.T) {
	P := Decaf448.NewElement()
	for _, vi := range kat.Invalid {
		for _, vj := range vi.Encodings {
			enc, err := hex.DecodeString(vj)
			test.CheckNoErr(t, err, "bad hex encoding")

			err = P.UnmarshalBinary(enc)
			test.CheckIsErr(t, err, "should trigger error: "+vi.Description)
		}
	}
}

func (kat *testJSONFile) oneway(t *testing.T) {
	var g decaf448
	var msg [2 * fp.Size]byte
	for _, vi := range kat.Oneway {
		input, err := hex.DecodeString(vi.Input)
		test.CheckNoErr(t, err, "bad hex encoding")
		test.CheckOk(len(input) == 2*fp.Size, "bad input size", t)

		copy(msg[:], input)
		P := g.oneway(&msg)
		got, err := P.MarshalBinary()
		test.CheckNoErr(t, err, "bad element marshalling")

		want, err := hex.DecodeString(vi.Output)
		test.CheckNoErr(t, err, "bad hex encoding")

		if !bytes.Equal(got, want) {
			test.ReportError(t, got, want, input)
		}
	}
}

func TestDecaf(t *testing.T) {
	var kat testJSONFile
	kat.readFile(t, "testdata/decaf_vectors.json")

	t.Run("multiples", kat.multiples)
	t.Run("invalid", kat.invalid)
	t.Run("oneway", kat.oneway)
}

func TestDecafInvalid(t *testing.T) {
	bigS := fp.P()
	negativeS := fp.Elt{1} // the smallest s that is negative
	nonQR := fp.Elt{4}     // the shortest s such that (a^2s^4 + (2a - 4d)*s^2 + 1) is non-QR.

	badEncodings := [][]byte{
		{},           // wrong size input
		bigS[:],      // s is out of the interval [0,p-1].
		negativeS[:], // s is not positive
		nonQR[:],     // s=4 and (a^2s^4 + (2a - 4d)*s^2 + 1) is non-QR.
	}

	e := decaf448{}.NewElement()
	for _, enc := range badEncodings {
		err := e.UnmarshalBinary(enc)
		test.CheckIsErr(t, err, "should trigger an error")
	}
}
