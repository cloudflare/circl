// @author Armando Faz

package x25519_test

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"strconv"
	"testing"

	x25519 "github.com/cloudflare/circl/ecc/x25519"
)

type WycheproofTestVector struct {
	TcId    int
	Public  [x25519.SizeKey]byte
	Private [x25519.SizeKey]byte
	Shared  [x25519.SizeKey]byte
}

func readVectors(t *testing.T) []WycheproofTestVector {
	type WycheproofRaw struct {
		TcId    int
		Comment string
		Curve   string
		Public  string
		Private string
		Shared  string
		Result  string
		Flags   []string
	}
	nameFile := "testdata/x25519_test.json"
	jsonFile, err := os.Open(nameFile)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", nameFile, err)
	}
	defer jsonFile.Close()

	input, _ := ioutil.ReadAll(jsonFile)
	var vectorsRaw []WycheproofRaw

	err = json.Unmarshal(input, &vectorsRaw)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", nameFile, err)
	}
	vectors := make([]WycheproofTestVector, len(vectorsRaw))
	for i, v := range vectorsRaw {
		vectors[i].TcId = v.TcId
		for j := 0; j < x25519.SizeKey; j++ {
			a, _ := strconv.ParseUint(v.Public[2*j:2*j+2], 16, 8)
			vectors[i].Public[j] = byte(a)
			a, _ = strconv.ParseUint(v.Private[2*j:2*j+2], 16, 8)
			vectors[i].Private[j] = byte(a)
			a, _ = strconv.ParseUint(v.Shared[2*j:2*j+2], 16, 8)
			vectors[i].Shared[j] = byte(a)
		}
	}
	return vectors
}

// TestWycheproof verifies test vectors from Wycheproof v0.4.12
func TestWycheproof(t *testing.T) {
	var got, want [x25519.SizeKey]byte

	vectors := readVectors(t)
	for _, v := range vectors {
		want = v.Shared
		x25519.ScalarMult(&got, &v.Private, &v.Public)
		if got != want {
			t.Errorf("Failed id: %v\ngot: %v\nwant:%v\n", v.TcId, got, want)
		}
	}
}
