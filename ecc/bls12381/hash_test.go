package bls12381

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381/ff"
	"github.com/cloudflare/circl/internal/test"
)

type vectorHash struct {
	SuiteID        string `json:"ciphersuite"`
	CurveName      string `json:"curve"`
	DST            string `json:"dst"`
	IsRandomOracle bool   `json:"randomOracle"`
	Vectors        []struct {
		P   point  `json:"P"`
		Msg string `json:"msg"`
	} `json:"vectors"`
}

type point struct {
	X string `json:"x"`
	Y string `json:"y"`
}

func (p point) toBytes() []byte {
	out := make([]byte, G1Size)
	x, err := hex.DecodeString(p.X[2:])
	if err != nil {
		panic(err)
	}
	copy(out[1*ff.FpSize-len(x):1*ff.FpSize], x)

	y, err := hex.DecodeString(p.Y[2:])
	if err != nil {
		panic(err)
	}
	copy(out[2*ff.FpSize-len(y):2*ff.FpSize], y)

	return out
}

func (v *vectorHash) test(t *testing.T) {
	got := new(G1)
	want := new(G1)
	dst := []byte(v.DST)

	doHash := got.Encode
	if v.IsRandomOracle {
		doHash = got.Hash
	}

	for i, vi := range v.Vectors {
		input := []byte(vi.Msg)
		doHash(input, dst)

		err := want.SetBytes(vi.P.toBytes())
		test.CheckNoErr(t, err, "bad deserialization")

		if !got.IsEqual(want) || !got.IsOnG1() {
			test.ReportError(t, got, want, v.SuiteID, i)
		}
	}
}

func readFile(t *testing.T, fileName string) *vectorHash {
	jsonFile, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", fileName, err)
	}
	defer jsonFile.Close()
	input, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", fileName, err)
	}
	v := new(vectorHash)
	err = json.Unmarshal(input, v)
	if err != nil {
		t.Fatalf("File %v can not be parsed. Error: %v", fileName, err)
	}
	return v
}

func TestHashVectors(t *testing.T) {
	// Test vectors from draft-irtf-cfrg-hash-to-curve:
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11
	//
	// JSON files can be found at:
	// https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/tree/draft-irtf-cfrg-hash-to-curve-10/poc/vectors

	fileNames, err := filepath.Glob("./testdata/BLS12381*.json")
	if err != nil {
		t.Fatal(err)
	}

	for _, fileName := range fileNames {
		v := readFile(t, fileName)
		t.Run(v.SuiteID, v.test)
	}
}
