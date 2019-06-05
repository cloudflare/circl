package x25519

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func hexStr2Key(s string, l int) []byte {
	k := make([]byte, l)
	for j := 0; j < len(k); j++ {
		a, _ := strconv.ParseUint(s[2*j:2*j+2], 16, 8)
		k[j] = byte(a)
	}
	return k
}

// Indicates wether long tests should be run
var runLongTest bool

func TestMain(m *testing.M) {
	flag.BoolVar(&runLongTest, "long", false, "runs longer tests")
	flag.Parse()
	os.Exit(m.Run())
}

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

	var dh X25519
	var priv, pub, got, want Key
	for _, v := range kat {
		copy(pub[:], hexStr2Key(v.Public, Size))
		copy(priv[:], hexStr2Key(v.Private, Size))
		dh.Shared(&got, &priv, &pub)
		copy(want[:], hexStr2Key(v.Shared, Size))
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

	var dh X25519
	var got, want Key
	for _, v := range kat {
		if !runLongTest && v.Times == uint32(1000000) {
			t.Log("Skipped one long test, add -long flag to run longer tests")
			continue
		}
		u := Key{9}
		k := u
		r := u
		for i := uint32(0); i < v.Times; i++ {
			dh.Shared(&r, &k, &u)
			u = k
			k = r
		}
		got = k
		copy(want[:], hexStr2Key(v.Key, Size))

		if got != want {
			test.ReportError(t, got, want, v.Times)
		}
	}
}

func TestBase(t *testing.T) {
	testTimes := 1 << 10
	var dh X25519
	var got, want, secret Key
	gen := Key{9}
	for i := 0; i < testTimes; i++ {
		_, _ = io.ReadFull(rand.Reader, secret[:])
		dh.KeyGen(&got, &secret)
		dh.Shared(&want, &secret, &gen)
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
	var dh X25519
	var got, want, priv, pub Key
	for _, v := range vecRaw {
		copy(pub[:], hexStr2Key(v.Public, Size))
		copy(priv[:], hexStr2Key(v.Private, Size))
		copy(want[:], hexStr2Key(v.Shared, Size))
		dh.Shared(&got, &priv, &pub)
		if got != want {
			test.ReportError(t, got, want, v.TcID, priv, pub)
		}
	}
}

func BenchmarkX25519(b *testing.B) {
	var dh X25519
	var x, y, z Key

	_, _ = io.ReadFull(rand.Reader, x[:])
	_, _ = io.ReadFull(rand.Reader, y[:])
	_, _ = io.ReadFull(rand.Reader, z[:])

	b.Run("KeyGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			dh.KeyGen(&x, &y)
		}
	})
	b.Run("Shared", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			dh.Shared(&z, &x, &y)
		}
	})
}

func Example_x25519() {
	var dh X25519
	var AliceSecret, BobSecret,
		AlicePublic, BobPublic,
		AliceShared, BobShared Key

	// Generating Alice's secret and public keys
	_, _ = io.ReadFull(rand.Reader, AliceSecret[:])
	dh.KeyGen(&AlicePublic, &AliceSecret)

	// Generating Bob's secret and public keys
	_, _ = io.ReadFull(rand.Reader, BobSecret[:])
	dh.KeyGen(&BobPublic, &BobSecret)

	// Deriving Alice's shared key
	dh.Shared(&AliceShared, &AliceSecret, &BobPublic)

	// Deriving Bob's shared key
	dh.Shared(&BobShared, &BobSecret, &AlicePublic)

	fmt.Println(AliceShared == BobShared)
	// Output: true
}
