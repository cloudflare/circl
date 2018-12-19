// +build amd64

package ecdhx_test

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"strconv"
	"testing"

	dh "github.com/cloudflare/circl/ecdhx"
)

type vector255 struct {
	Input, Output, Scalar dh.Key255
}

type vector448 struct {
	Input, Output, Scalar dh.Key448
}

func stringToSlice(s string, len int) []byte {
	z := make([]byte, len)
	for j := 0; j < len; j++ {
		a, _ := strconv.ParseUint(s[2*j:2*j+2], 16, 8)
		z[j] = byte(a)
	}
	return z
}

func readKatVectors(t *testing.T) (v0 []vector255, v1 []vector448) {
	nameFile := "testdata/rfc7748_kat_test.json"
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
	v0 = make([]vector255, len(vectorsRaw.X25519))
	for i, v := range vectorsRaw.X25519 {
		copy(v0[i].Input[:], stringToSlice(v.Input, dh.SizeKey255))
		copy(v0[i].Output[:], stringToSlice(v.Output, dh.SizeKey255))
		copy(v0[i].Scalar[:], stringToSlice(v.Scalar, dh.SizeKey255))
	}
	v1 = make([]vector448, len(vectorsRaw.X448))
	for i, v := range vectorsRaw.X448 {
		copy(v1[i].Input[:], stringToSlice(v.Input, dh.SizeKey448))
		copy(v1[i].Output[:], stringToSlice(v.Output, dh.SizeKey448))
		copy(v1[i].Scalar[:], stringToSlice(v.Scalar, dh.SizeKey448))
	}
	return v0, v1
}

func TestRFC7748Kat(t *testing.T) {
	v0, v1 := readKatVectors(t)
	t.Run("X25519", func(t *testing.T) {
		for _, v := range v0 {
			got := v.Scalar.Shared(v.Input)
			want := v.Output
			if got != want {
				t.Errorf("Failed\ngot: %v\nwant:%v\n", got, want)
			}
		}
	})
	t.Run("X448", func(t *testing.T) {
		for _, v := range v1 {
			got := v.Scalar.Shared(v.Input)
			want := v.Output
			if got != want {
				t.Errorf("Failed\ngot: %v\nwant:%v\n", got, want)
			}
		}
	})
}

func readTimeVectors(t *testing.T) (map[uint32]dh.Key255, map[uint32]dh.Key448) {
	nameFile := "testdata/rfc7748_times_test.json"
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
	v0 := make(map[uint32]dh.Key255)
	for _, v := range vectorsRaw.X25519 {
		var key dh.Key255
		copy(key[:], stringToSlice(v.Key, dh.SizeKey255))
		v0[v.Times] = key
	}
	v1 := make(map[uint32]dh.Key448)
	for _, v := range vectorsRaw.X448 {
		var key dh.Key448
		copy(key[:], stringToSlice(v.Key, dh.SizeKey448))
		v1[v.Times] = key
	}
	return v0, v1
}

func TestRFC7748Times(t *testing.T) {
	v0, v1 := readTimeVectors(t)
	t.Run("X25519", func(t *testing.T) {
		for times, want := range v0 {
			u := dh.GetBase255()
			k := dh.GetBase255()
			switch {
			case testing.Short() && times == uint32(1000000):
				t.Log("Skipped one long test")
				continue
			case times == uint32(1000000):
				t.Log("This is a long test")
			}
			for i := uint32(0); i < times; i++ {
				r := k.Shared(u)
				u = k
				k = r
			}
			got := k
			if got != want {
				t.Errorf("[incorrect result]\ngot:  %v\nwant: %v\n", got, want)
			}
		}
	})
	t.Run("X448", func(t *testing.T) {
		for times, want := range v1 {
			u := dh.GetBase448()
			k := dh.GetBase448()
			switch {
			case testing.Short() && times == uint32(1000000):
				t.Log("Skipped one long test")
				continue
			case times == uint32(1000000):
				t.Log("This is a long test")
			}
			for i := uint32(0); i < times; i++ {
				r := k.Shared(u)
				u = k
				k = r
			}
			got := k
			if got != want {
				t.Errorf("[incorrect result]\ngot:  %v\nwant: %v\n", got, want)
			}
		}
	})
}
