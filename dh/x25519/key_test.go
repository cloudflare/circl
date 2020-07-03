package x25519

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func hexStr2Key(k *Key, s string) {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("Can't convert string to key")
	}
	copy(k[:], b)
}

// Indicates whether long tests should be run
var runLongTest = flag.Bool("long", false, "runs longer tests")

type katVector struct {
	Public  string `json:"input"`
	Shared  string `json:"output"`
	Private string `json:"scalar"`
}

func TestRFC7748Kat(t *testing.T) {
	const nameFile = "testdata/rfc7748_kat_test.json"
	var kat []katVector

	jsonFile, err := os.Open(nameFile)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", nameFile, err)
	}
	defer jsonFile.Close()
	input, _ := ioutil.ReadAll(jsonFile)

	err = json.Unmarshal(input, &kat)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", nameFile, err)
	}

	var priv, pub, got, want Key
	for _, v := range kat {
		hexStr2Key(&pub, v.Public)
		hexStr2Key(&priv, v.Private)
		Shared(&got, &priv, &pub)
		hexStr2Key(&want, v.Shared)
		if got != want {
			test.ReportError(t, got, want, v)
		}
	}
}

type katTimes struct {
	Times uint32 `json:"times"`
	Key   string `json:"key"`
}

func TestRFC7748Times(t *testing.T) {
	const nameFile = "testdata/rfc7748_times_test.json"
	jsonFile, err := os.Open(nameFile)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", nameFile, err)
	}
	defer jsonFile.Close()
	input, _ := ioutil.ReadAll(jsonFile)

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
		hexStr2Key(&want, v.Key)

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
	const nameFile = "testdata/wycheproof_kat.json"
	jsonFile, err := os.Open(nameFile)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", nameFile, err)
	}
	defer jsonFile.Close()

	input, _ := ioutil.ReadAll(jsonFile)
	var vecRaw []struct {
		TcID    int      `json:"tcId"`
		Comment string   `json:"comment"`
		Curve   string   `json:"curve"`
		Public  string   `json:"public"`
		Private string   `json:"private"`
		Shared  string   `json:"shared"`
		Result  string   `json:"result"`
		Flags   []string `json:"flags"`
	}

	err = json.Unmarshal(input, &vecRaw)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", nameFile, err)
	}
	var got, want, priv, pub Key
	for _, v := range vecRaw {
		hexStr2Key(&pub, v.Public)
		hexStr2Key(&priv, v.Private)
		hexStr2Key(&want, v.Shared)
		ok := Shared(&got, &priv, &pub)
		if got != want {
			test.ReportError(t, got, want, v.TcID, priv, pub)
		}
		if !ok && v.Result != "acceptable" {
			test.ReportError(t, got, want, v.TcID, priv, pub)
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
