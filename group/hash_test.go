package group_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/internal/test"
)

func TestHashToElement(t *testing.T) {
	fileNames, err := filepath.Glob("./testdata/P*.json")
	if err != nil {
		t.Fatal(err)
	}

	for _, fileName := range fileNames {
		f, err := os.Open(fileName)
		if err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(f)
		var v vectorSuite
		err = dec.Decode(&v)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()

		t.Run(v.Ciphersuite, func(t *testing.T) { testHashing(t, &v) })
	}
}

func testHashing(t *testing.T, vs *vectorSuite) {
	var G group.Group
	switch vs.Ciphersuite[0:4] {
	case "P256":
		G = group.P256
	case "P384":
		G = group.P384
	case "P521":
		G = group.P521
	default:
		t.Fatal("non supported suite")
	}

	hashFunc := G.HashToElement
	if !vs.RandomOracle {
		hashFunc = G.HashToElementNonUniform
	}

	want := G.NewElement()
	for i, v := range vs.Vectors {
		got := hashFunc([]byte(v.Msg), []byte(vs.Dst))
		err := want.UnmarshalBinary(v.P.toBytes())
		if err != nil {
			t.Fatal(err)
		}

		if !got.IsEqual(want) {
			test.ReportError(t, got, want, i)
		}
	}
}

type vectorSuite struct {
	L           string `json:"L"`
	Z           string `json:"Z"`
	Ciphersuite string `json:"ciphersuite"`
	Curve       string `json:"curve"`
	Dst         string `json:"dst"`
	Expand      string `json:"expand"`
	Field       struct {
		M string `json:"m"`
		P string `json:"p"`
	} `json:"field"`
	Hash string `json:"hash"`
	K    string `json:"k"`
	Map  struct {
		Name string `json:"name"`
	} `json:"map"`
	RandomOracle bool     `json:"randomOracle"`
	Vectors      []vector `json:"vectors"`
}

type point struct {
	X string `json:"x"`
	Y string `json:"y"`
}

func (p point) toBytes() []byte {
	x, err := hex.DecodeString(p.X[2:])
	if err != nil {
		panic(err)
	}
	y, err := hex.DecodeString(p.Y[2:])
	if err != nil {
		panic(err)
	}
	return append(append([]byte{0x04}, x...), y...)
}

type vector struct {
	P   point    `json:"P"`
	Q0  point    `json:"Q0,omitempty"`
	Q1  point    `json:"Q1,omitempty"`
	Q   point    `json:"Q,omitempty"`
	Msg string   `json:"msg"`
	U   []string `json:"u"`
}

func BenchmarkHash(b *testing.B) {
	for _, g := range allGroups {
		g := g
		name := g.(fmt.Stringer).String()
		b.Run(name+"/HashToElement", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				g.HashToElement(nil, nil)
			}
		})
		b.Run(name+"/HashToElementNonUniform", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				g.HashToElementNonUniform(nil, nil)
			}
		})
		b.Run(name+"/HashToScalar", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				g.HashToScalar(nil, nil)
			}
		})
	}
}
