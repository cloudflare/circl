package decaf_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/circl/ecc/decaf"
	"github.com/cloudflare/circl/internal/test"
	fp "github.com/cloudflare/circl/math/fp448"
)

type testJSONFile struct {
	Group     string `json:"group"`
	Version   string `json:"version"`
	Generator struct {
		X string `json:"x"`
		Y string `json:"y"`
		T string `json:"t"`
		Z string `json:"z"`
	} `json:"generator"`
	Vectors []struct {
		K  string `json:"k"`
		KG string `json:"kG"`
		KP string `json:"kP"`
	} `json:"vectors"`
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

func verify(t *testing.T, i int, gotkG *decaf.Elt, wantEnckG []byte) {
	wantkG := &decaf.Elt{}

	gotEnckG, err := gotkG.MarshalBinary()
	got := err == nil && bytes.Equal(gotEnckG, wantEnckG)
	want := true
	if got != want {
		test.ReportError(t, got, want, i)
	}

	err = wantkG.UnmarshalBinary(wantEnckG)
	got = err == nil &&
		decaf.IsValid(gotkG) &&
		decaf.IsValid(wantkG) &&
		gotkG.IsEqual(wantkG)
	want = true
	if got != want {
		test.ReportError(t, got, want, i)
	}
}

// Source: https://gist.github.com/armfazh/af01e1794dcf6942f2d404c5a0832676
func TestDecafv1_0(t *testing.T) {
	var kat testJSONFile
	kat.readFile(t, "testdata/decafv1.0_vectors.json")

	got := kat.Group
	want := "decaf"
	if got != want {
		test.ReportError(t, got, want)
	}
	got = kat.Version
	want = decaf.Version
	if got != want {
		test.ReportError(t, got, want)
	}
	var scalar decaf.Scalar
	var P decaf.Elt
	G := decaf.Generator()
	for i := range kat.Vectors {
		k, _ := hex.DecodeString(kat.Vectors[i].K)
		wantEnckG, _ := hex.DecodeString(kat.Vectors[i].KG)
		wantEnckP, _ := hex.DecodeString(kat.Vectors[i].KP)
		scalar.FromBytes(k)

		decaf.MulGen(&P, &scalar)
		verify(t, i, &P, wantEnckG)

		decaf.Mul(&P, &scalar, G)
		verify(t, i, &P, wantEnckG)

		decaf.Mul(&P, &scalar, &P)
		verify(t, i, &P, wantEnckP)
	}
}

func TestDecafRandom(t *testing.T) {
	const testTimes = 1 << 10
	var e decaf.Elt
	var enc [decaf.EncodingSize]byte

	for i := 0; i < testTimes; i++ {
		for found := false; !found; {
			_, _ = rand.Read(enc[:])
			err := e.UnmarshalBinary(enc[:])
			found = err == nil
		}
		got, err := e.MarshalBinary()
		want := enc[:]
		if err != nil || !bytes.Equal(got, want) {
			test.ReportError(t, got, want, e)
		}
	}
}

func randomPoint() decaf.Elt {
	var k decaf.Scalar
	_, _ = rand.Read(k[:])
	var P decaf.Elt
	decaf.MulGen(&P, &k)
	return P
}

func TestPointAdd(t *testing.T) {
	const testTimes = 1 << 10
	Q := &decaf.Elt{}
	for i := 0; i < testTimes; i++ {
		P := randomPoint()
		// Q = 16P = 2^4P
		decaf.Double(Q, &P) // 2P
		decaf.Double(Q, Q)  // 4P
		decaf.Double(Q, Q)  // 8P
		decaf.Double(Q, Q)  // 16P
		got := Q
		// R = 16P = P+P...+P
		R := decaf.Identity()
		for j := 0; j < 16; j++ {
			decaf.Add(R, R, &P)
		}
		want := R
		if !decaf.IsValid(got) || !decaf.IsValid(want) || !got.IsEqual(want) {
			test.ReportError(t, got, want, P)
		}
	}
}

func TestPointNeg(t *testing.T) {
	const testTimes = 1 << 10
	Q := &decaf.Elt{}
	for i := 0; i < testTimes; i++ {
		P := randomPoint()
		decaf.Neg(Q, &P)
		decaf.Add(Q, Q, &P)
		got := Q.IsIdentity()
		want := true
		if got != want {
			test.ReportError(t, got, want, P)
		}
	}
}

func TestDecafOrder(t *testing.T) {
	const testTimes = 1 << 10
	Q := &decaf.Elt{}
	order := decaf.Order()
	for i := 0; i < testTimes; i++ {
		P := randomPoint()

		decaf.Mul(Q, &order, &P)
		got := Q.IsIdentity()
		want := true
		if got != want {
			test.ReportError(t, got, want, P, order)
		}
	}
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

	var e decaf.Elt
	for _, enc := range badEncodings {
		got := e.UnmarshalBinary(enc)
		want := decaf.ErrInvalidDecoding
		if got != want {
			test.ReportError(t, got, want, enc)
		}
	}
}

func BenchmarkDecaf(b *testing.B) {
	var k, l decaf.Scalar
	_, _ = rand.Read(k[:])
	_, _ = rand.Read(l[:])
	G := decaf.Generator()
	P := decaf.Generator()
	enc, _ := G.MarshalBinary()

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decaf.Add(P, P, G)
		}
	})
	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decaf.Mul(G, &k, G)
		}
	})
	b.Run("MulGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decaf.MulGen(P, &k)
		}
	})
	b.Run("Marshal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = G.MarshalBinary()
		}
	})
	b.Run("Unmarshal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = P.UnmarshalBinary(enc)
		}
	})
}
