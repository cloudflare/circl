package bls12381

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	Field struct {
		M string `json:"m"`
		P string `json:"p"`
	} `json:"field"`
}

type elm string

func (e elm) toBytes(t *testing.T) (out []byte) {
	var buf [ff.FpSize]byte
	for _, s := range strings.Split(string(e), ",") {
		x, err := hex.DecodeString(s[2:])
		if err != nil {
			t.Fatal(err)
		}
		copy(buf[ff.FpSize-len(x):ff.FpSize], x)
		out = append(append([]byte{}, buf[:]...), out...)
	}
	return
}

type point struct {
	X elm `json:"x"`
	Y elm `json:"y"`
}

func (p point) toBytes(t *testing.T) []byte { return append(p.X.toBytes(t), p.Y.toBytes(t)...) }

type hasher interface {
	Encode(_, _ []byte)
	Hash(_, _ []byte)
	SetBytes([]byte) error
	IsEqualTo(_ hasher) bool
	IsRTorsion() bool
}

type g1Hasher struct{ *G1 }

func (g g1Hasher) IsEqualTo(x hasher) bool { return g.IsEqual(x.(g1Hasher).G1) }
func (g g1Hasher) IsRTorsion() bool        { return g.IsOnG1() }

type g2Hasher struct{ *G2 }

func (g g2Hasher) IsEqualTo(x hasher) bool { return g.IsEqual(x.(g2Hasher).G2) }
func (g g2Hasher) IsRTorsion() bool        { return g.IsOnG2() }

func (v *vectorHash) test(t *testing.T) {
	var got, want hasher
	if v.Field.M == "0x1" {
		got, want = g1Hasher{new(G1)}, g1Hasher{new(G1)}
	} else if v.Field.M == "0x2" {
		got, want = g2Hasher{new(G2)}, g2Hasher{new(G2)}
	}

	dst := []byte(v.DST)

	doHash := got.Encode
	if v.IsRandomOracle {
		doHash = got.Hash
	}

	for i, vi := range v.Vectors {
		input := []byte(vi.Msg)
		doHash(input, dst)

		err := want.SetBytes(vi.P.toBytes(t))
		test.CheckNoErr(t, err, "bad deserialization")

		if !got.IsEqualTo(want) || !got.IsRTorsion() {
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
	input, err := io.ReadAll(jsonFile)
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
