package bls12381

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func isEqual(p, q interface{}) bool {
	switch P := p.(type) {
	case *G1:
		return P.IsEqual(q.(*G1))
	case *G2:
		return P.IsEqual(q.(*G2))
	default:
		panic("bad type")
	}
}

func addGenerator(p interface{}) {
	switch P := p.(type) {
	case *G1:
		P.Add(P, G1Generator())
	case *G2:
		P.Add(P, G2Generator())
	default:
		panic("bad type")
	}
}

func testSerialVector(t *testing.T, file io.Reader, v *serialVector) {
	var bP []byte
	bQ := make([]byte, v.length)
	v.P.SetIdentity()
	for i := 0; i < 1000; i++ {
		n, err := file.Read(bQ)
		if n != v.length || err != nil {
			t.Fatalf("error reading %v file: %v", v.fileName, err)
		}
		test.CheckNoErr(t, v.Q.SetBytes(bQ), "failed deserialization")

		if !isEqual(v.P, v.Q) {
			test.ReportError(t, v.P, v.Q, i)
		}

		if v.compressed {
			bP = v.P.BytesCompressed()
		} else {
			bP = v.P.Bytes()
		}
		if !bytes.Equal(bP, bQ) {
			test.ReportError(t, bP, bQ, i)
		}
		addGenerator(v.P)
	}
}

type serialVector struct {
	fileName   string
	length     int
	compressed bool
	P, Q       interface {
		SetIdentity()
		SetBytes([]byte) error
		Bytes() []byte
		BytesCompressed() []byte
	}
}

func TestSerializationVector(t *testing.T) {
	for _, vv := range []serialVector{
		{"g1_uncompressed", G1Size, false, new(G1), new(G1)},
		{"g1_compressed", G1SizeCompressed, true, new(G1), new(G1)},
		{"g2_uncompressed", G2Size, false, new(G2), new(G2)},
		{"g2_compressed", G2SizeCompressed, true, new(G2), new(G2)},
	} {
		v := vv
		file, err := os.Open("testdata/" + v.fileName + "_valid_test_vectors.dat")
		if err != nil {
			t.Fatalf("file %v can not be opened: %v", v.fileName, err)
		}
		defer file.Close()

		t.Run(v.fileName[:7], func(t *testing.T) { testSerialVector(t, file, &v) })
	}
}
