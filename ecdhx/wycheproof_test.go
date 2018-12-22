// +build amd64

package ecdhx_test

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	dh "github.com/cloudflare/circl/ecdhx"
)

type WycheproofTestVector struct {
	TcId    int
	Public  dh.XKey
	Private dh.XKey
	Shared  dh.XKey
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
		vectors[i].Public = stringToKey(v.Public, dh.SizeKey255)
		vectors[i].Private = stringToKey(v.Private, dh.SizeKey255)
		vectors[i].Shared = stringToKey(v.Shared, dh.SizeKey255)
	}
	return vectors
}

// TestWycheproof verifies test vectors from Wycheproof v0.4.12
func TestWycheproof(t *testing.T) {
	vectors := readVectors(t)
	for _, v := range vectors {
		want := v.Shared
		got := v.Private.Shared(v.Public)
		if got != want {
			t.Errorf("Failed id: %v\ngot: %v\nwant:%v\n", v.TcId, got, want)
		}
	}
}
