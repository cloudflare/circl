// +build amd64

package ecdhx

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"testing"

	dh "github.com/cloudflare/circl/ecdhx"
)

type katVector struct {
	TcId    int
	Public  dh.XKey
	Private dh.XKey
	Shared  dh.XKey
}

type timesVector struct {
	T uint32
	W dh.XKey
}

func strToKey(s string, l int) dh.XKey {
	z := make([]byte, l)
	for j := 0; j < l; j++ {
		a, _ := strconv.ParseUint(s[2*j:2*j+2], 16, 8)
		z[j] = byte(a)
	}
	return dh.XKeyFromSlice(z)
}

// Indicates wether long tests should be run
var runLongTest bool

func TestMain(m *testing.M) {
	flag.BoolVar(&runLongTest, "long", false, "runs longer tests")
	flag.Parse()
	os.Exit(m.Run())
}

func testVector(t *testing.T, v katVector) {
	got, want := v.Private.Shared(v.Public), v.Shared
	if got != want {
		t.Errorf("Failed\ngot: %v\nwant:%v\n", got, want)
	}
}

// Tests
func baseTest(t *testing.T, x, base dh.XKey) {
	const times = 1 << 10
	y := x
	for i := 0; i < times; i++ {
		want, got := x.Shared(base), y.KeyGen()
		x, y = want, got
		if got != want {
			t.Errorf("[incorrect result]\ninput: %v\ngot:   %v\nwant:  %v\n", x, got, want)
		}
	}
}

func TestBaseECDHXx255(t *testing.T) { baseTest(t, dh.RandomKey255(), dh.GetBase255()) }
func TestBaseECDHXx448(t *testing.T) { baseTest(t, dh.RandomKey448(), dh.GetBase448()) }

func TestRFC7748Kat(t *testing.T) {
	readKatVectors := func(t *testing.T, nameFile string) (r []katVector) {
		var kat struct {
			X25519, X448 []struct {
				Public  string `json:"input"`
				Shared  string `json:"output"`
				Private string `json:"scalar"`
			}
		}

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

		l := dh.SizeKey255
		for _, v := range kat.X25519 {
			r = append(r, katVector{
				Public:  strToKey(v.Public, l),
				Shared:  strToKey(v.Shared, l),
				Private: strToKey(v.Private, l),
			})
		}
		l = dh.SizeKey448
		for _, v := range kat.X448 {
			r = append(r, katVector{
				Public:  strToKey(v.Public, l),
				Shared:  strToKey(v.Shared, l),
				Private: strToKey(v.Private, l),
			})
		}
		return r
	}

	for _, v := range readKatVectors(t, "testdata/rfc7748_kat_test.json") {
		testVector(t, v)
	}
}

func TestRFC7748Times(t *testing.T) {
	var u dh.XKey

	readTimeVectors := func(t *testing.T, nameFile string) (r []timesVector) {
		jsonFile, err := os.Open(nameFile)
		if err != nil {
			t.Fatalf("File %v can not be opened. Error: %v", nameFile, err)
		}
		defer jsonFile.Close()
		input, _ := ioutil.ReadAll(jsonFile)

		var kat struct {
			X25519, X448 []struct {
				Times uint32 `json:"times"`
				Key   string `json:"key"`
			}
		}
		err = json.Unmarshal(input, &kat)
		if err != nil {
			t.Fatalf("File %v can not be loaded. Error: %v", nameFile, err)
		}
		for _, v := range kat.X25519 {
			r = append(r, timesVector{
				T: v.Times,
				W: strToKey(v.Key, dh.SizeKey255),
			})
		}
		for _, v := range kat.X448 {
			r = append(r, timesVector{
				T: v.Times,
				W: strToKey(v.Key, dh.SizeKey448),
			})
		}
		return r
	}

	for _, v := range readTimeVectors(t, "testdata/rfc7748_times_test.json") {
		if !runLongTest && v.T == uint32(1000000) {
			t.Log("Skipped one long test, add -long flag to run longer tests")
			continue
		}
		switch v.W.Size() {
		case dh.SizeKey255:
			u = dh.GetBase255()
		case dh.SizeKey448:
			u = dh.GetBase448()
		}
		k := u
		for i := uint32(0); i < v.T; i++ {
			r := k.Shared(u)
			u = k
			k = r
		}
		got, want := k, v.W
		if got != want {
			t.Errorf("[incorrect result]\ngot:  %v\nwant: %v\n", got, want)
		}
	}
}

// TestWycheproof verifies test vectors from Wycheproof v0.4.12
func TestWycheproof(t *testing.T) {

	readVectors := func(t *testing.T) []katVector {
		jsonFile, err := os.Open("testdata/wycheproof_kat.json")
		if err != nil {
			t.Fatalf("Error: %v", err)
		}
		defer jsonFile.Close()

		input, _ := ioutil.ReadAll(jsonFile)
		var vecRaw []struct {
			TcId    int
			Comment string
			Curve   string
			Public  string
			Private string
			Shared  string
			Result  string
			Flags   []string
		}

		err = json.Unmarshal(input, &vecRaw)
		if err != nil {
			t.Fatalf("Error: %v", err)
		}
		vec := make([]katVector, len(vecRaw))
		for i, v := range vecRaw {
			vec[i].TcId = v.TcId
			vec[i].Public = strToKey(v.Public, dh.SizeKey255)
			vec[i].Private = strToKey(v.Private, dh.SizeKey255)
			vec[i].Shared = strToKey(v.Shared, dh.SizeKey255)
		}
		return vec
	}

	for _, v := range readVectors(t) {
		testVector(t, v)
	}
}

// Benchmarks
func benchECDH(b *testing.B, x, y dh.XKey) {
	b.SetBytes(int64(x.Size()))
	b.Run("KeyGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x = x.KeyGen()
		}
	})
	b.Run("Shared", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z := x.Shared(y)
			y = x
			x = z
		}
	})
}

func BenchmarkECDHXx255(b *testing.B) { benchECDH(b, dh.RandomKey255(), dh.RandomKey255()) }
func BenchmarkECDHXx448(b *testing.B) { benchECDH(b, dh.RandomKey448(), dh.RandomKey448()) }

func Example_x25519() {
	// Generating Alice's secret and public keys
	aliceSecret := dh.RandomKey255()
	alicePublic := aliceSecret.KeyGen()
	// Generating Bob's secret and public keys
	bobSecret := dh.RandomKey255()
	bobPublic := bobSecret.KeyGen()
	// Deriving Alice's shared key
	aliceShared := aliceSecret.Shared(bobPublic)
	// Deriving Bob's shared key
	bobShared := bobSecret.Shared(alicePublic)

	fmt.Println(aliceShared == bobShared)
	// Output: true
}
