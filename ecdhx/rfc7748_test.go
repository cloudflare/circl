// +build amd64

package ecdhx_test

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
	"strconv"
	"testing"

	dh "github.com/cloudflare/circl/ecdhx"
)

var long bool

func TestMain(m *testing.M) {
	flag.BoolVar(&long, "long", false, "runs longer tests")
	flag.Parse()
	os.Exit(m.Run())
}

func stringToKey(s string, l int) dh.XKey {
	z := make([]byte, l)
	for j := 0; j < l; j++ {
		a, _ := strconv.ParseUint(s[2*j:2*j+2], 16, 8)
		z[j] = byte(a)
	}
	return dh.XKeyFromSlice(z)
}

type katVector struct{ Input, Output, Scalar dh.XKey }

func readKatVectors(t *testing.T, nameFile string) (r []katVector) {
	jsonFile, err := os.Open(nameFile)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", nameFile, err)
	}
	defer jsonFile.Close()
	input, _ := ioutil.ReadAll(jsonFile)

	var vectorsRaw struct {
		X25519, X448 []struct {
			Input  string `json:"input"`
			Output string `json:"output"`
			Scalar string `json:"scalar"`
		}
	}
	err = json.Unmarshal(input, &vectorsRaw)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", nameFile, err)
	}
	l := dh.SizeKey255
	for _, v := range vectorsRaw.X25519 {
		r = append(r, katVector{
			Input:  stringToKey(v.Input, l),
			Output: stringToKey(v.Output, l),
			Scalar: stringToKey(v.Scalar, l),
		})
	}
	l = dh.SizeKey448
	for _, v := range vectorsRaw.X448 {
		r = append(r, katVector{
			Input:  stringToKey(v.Input, l),
			Output: stringToKey(v.Output, l),
			Scalar: stringToKey(v.Scalar, l),
		})
	}
	return r
}

func TestRFC7748Kat(t *testing.T) {
	V := readKatVectors(t, "testdata/rfc7748_kat_test.json")
	for _, v := range V {
		got, want := v.Scalar.Shared(v.Input), v.Output
		if got != want {
			t.Errorf("Failed\ngot: %v\nwant:%v\n", got, want)
		}
	}
}

type timesVector struct {
	T uint32
	W dh.XKey
}

func readTimeVectors(t *testing.T, nameFile string) (r []timesVector) {
	jsonFile, err := os.Open(nameFile)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", nameFile, err)
	}
	defer jsonFile.Close()
	input, _ := ioutil.ReadAll(jsonFile)

	var vectorsRaw struct {
		X25519, X448 []struct {
			Times uint32 `json:"times"`
			Key   string `json:"key"`
		}
	}
	err = json.Unmarshal(input, &vectorsRaw)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", nameFile, err)
	}
	for _, v := range vectorsRaw.X25519 {
		r = append(r, timesVector{
			T: v.Times,
			W: stringToKey(v.Key, dh.SizeKey255),
		})
	}
	for _, v := range vectorsRaw.X448 {
		r = append(r, timesVector{
			T: v.Times,
			W: stringToKey(v.Key, dh.SizeKey448),
		})
	}
	return r
}

func TestRFC7748Times(t *testing.T) {
	var u dh.XKey
	V := readTimeVectors(t, "testdata/rfc7748_times_test.json")
	for _, v := range V {
		if !long && v.T == uint32(1000000) {
			t.Log("Skipped one long test, add -long flag to run longer tests")
			continue
		}
		switch v.W.Size() {
		case dh.SizeKey255:
			u = dh.GetBase255()
		case dh.SizeKey448:
			u = dh.GetBase448()
		}
		k := u
		for i := uint32(0); i < v.T; i++ {
			r := k.Shared(u)
			u = k
			k = r
		}
		got, want := k, v.W
		if got != want {
			t.Errorf("[incorrect result]\ngot:  %v\nwant: %v\n", got, want)
		}
	}
}
