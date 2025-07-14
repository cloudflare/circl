package x25519

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

// Indicates whether long tests should be run
var runLongTest = flag.Bool("long", false, "runs longer tests")

type katVector struct {
	Public  test.HexBytes `json:"input"`
	Shared  test.HexBytes `json:"output"`
	Private test.HexBytes `json:"scalar"`
}

func TestRFC7748Kat(t *testing.T) {
	const nameFile = "testdata/rfc7748_kat_test.json.gz"
	var kat []katVector
	input, err := test.ReadGzip(nameFile)
	if err != nil {
		t.Fatalf("File %v can not be read. Error: %v", nameFile, err)
	}

	err = json.Unmarshal(input, &kat)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", nameFile, err)
	}

	var got Key
	for _, v := range kat {
		pub := Key(v.Public)
		priv := Key(v.Private)
		Shared(&got, &priv, &pub)
		want := Key(v.Shared)
		if got != want {
			test.ReportError(t, got, want, v)
		}
	}
}

type katTimes struct {
	Times uint32        `json:"times"`
	Key   test.HexBytes `json:"key"`
}

func TestRFC7748Times(t *testing.T) {
	const nameFile = "testdata/rfc7748_times_test.json.gz"
	input, err := test.ReadGzip(nameFile)
	if err != nil {
		t.Fatalf("File %v can not be read. Error: %v", nameFile, err)
	}

	var kat []katTimes
	err = json.Unmarshal(input, &kat)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", nameFile, err)
	}

	var got, want Key
	for _, v := range kat {
		if !*runLongTest && v.Times == uint32(1000000) {
			t.Log("Skipped one long test, add -long flag to run longer tests")
			continue
		}
		u := Key{9}
		k := u
		r := u
		for i := uint32(0); i < v.Times; i++ {
			Shared(&r, &k, &u)
			u = k
			k = r
		}
		got = k
		copy(want[:], v.Key)

		if got != want {
			test.ReportError(t, got, want, v.Times)
		}
	}
}

func TestBase(t *testing.T) {
	testTimes := 1 << 10
	var got, want, secret Key
	gen := Key{9}
	for i := 0; i < testTimes; i++ {
		_, _ = io.ReadFull(rand.Reader, secret[:])
		KeyGen(&got, &secret)
		Shared(&want, &secret, &gen)
		if got != want {
			test.ReportError(t, got, want, secret)
		}
	}
}

func TestWycheproof(t *testing.T) {
	// Test vectors from Wycheproof v0.4.12
	const nameFile = "testdata/wycheproof_kat.json.gz"
	input, err := test.ReadGzip(nameFile)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", nameFile, err)
	}

	var vecRaw []struct {
		TcID    int           `json:"tcId"`
		Comment string        `json:"comment"`
		Curve   string        `json:"curve"`
		Public  test.HexBytes `json:"public"`
		Private test.HexBytes `json:"private"`
		Shared  test.HexBytes `json:"shared"`
		Result  string        `json:"result"`
		Flags   []string      `json:"flags"`
	}

	err = json.Unmarshal(input, &vecRaw)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", nameFile, err)
	}

	var got Key
	for _, v := range vecRaw {
		pub := Key(v.Public)
		priv := Key(v.Private)
		ok := Shared(&got, &priv, &pub)
		want := Key(v.Shared)
		if got != want {
			test.ReportError(t, got, want, v.TcID, v.Private, v.Public)
		}
		if !ok && v.Result != "acceptable" {
			test.ReportError(t, got, want, v.TcID, v.Private, v.Public)
		}
	}
}

func BenchmarkX25519(b *testing.B) {
	var x, y, z Key

	_, _ = io.ReadFull(rand.Reader, x[:])
	_, _ = io.ReadFull(rand.Reader, y[:])
	_, _ = io.ReadFull(rand.Reader, z[:])

	b.Run("KeyGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			KeyGen(&x, &y)
		}
	})
	b.Run("Shared", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Shared(&z, &x, &y)
		}
	})
}

func Example_x25519() {
	var AliceSecret, BobSecret,
		AlicePublic, BobPublic,
		AliceShared, BobShared Key

	// Generating Alice's secret and public keys
	_, _ = io.ReadFull(rand.Reader, AliceSecret[:])
	KeyGen(&AlicePublic, &AliceSecret)

	// Generating Bob's secret and public keys
	_, _ = io.ReadFull(rand.Reader, BobSecret[:])
	KeyGen(&BobPublic, &BobSecret)

	// Deriving Alice's shared key
	okA := Shared(&AliceShared, &AliceSecret, &BobPublic)

	// Deriving Bob's shared key
	okB := Shared(&BobShared, &BobSecret, &AlicePublic)

	fmt.Println(AliceShared == BobShared && okA && okB)
	// Output: true
}
