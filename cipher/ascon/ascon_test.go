package ascon_test

import (
	"bytes"
	hexa "encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"testing"

	"github.com/cloudflare/circl/cipher/ascon"
	"github.com/cloudflare/circl/internal/test"
)

type vector struct {
	Count int `json:"Count"`
	Key   hex `json:"Key"`
	Nonce hex `json:"Nonce"`
	PT    hex `json:"PT"`
	AD    hex `json:"AD"`
	CT    hex `json:"CT"`
}

type hex []byte

func (h *hex) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	decoded, err := hexa.DecodeString(s)
	if err != nil {
		return err
	}
	*h = hex(decoded)
	return nil
}

func readFile(t *testing.T, fileName string) []vector {
	jsonFile, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", fileName, err)
	}
	defer jsonFile.Close()
	input, err := io.ReadAll(jsonFile)
	if err != nil {
		t.Fatalf("File %v can not be read. Error: %v", fileName, err)
	}
	var v []vector
	err = json.Unmarshal(input, &v)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", fileName, err)
	}
	return v
}

func TestAscon(t *testing.T) {
	// Test vectors generated with pyascon
	// https://github.com/meichlseder/pyascon/
	for _, cipher := range []struct {
		mode ascon.Mode
		name string
	}{
		{ascon.Ascon128, "ascon128"},
		{ascon.Ascon128a, "ascon128a"},
	} {
		t.Run(cipher.name, func(t *testing.T) {
			vectors := readFile(t, "testdata/"+cipher.name+".json")
			for _, v := range vectors {
				a, err := ascon.New(v.Key, cipher.mode)
				if err != nil {
					t.Fatal(err)
				}
				got := a.Seal(nil, v.Nonce, v.PT, v.AD)
				want := v.CT
				if !bytes.Equal(got, want) {
					test.ReportError(t, got, want, cipher.name, v.Count)
				}

				got, err = a.Open(nil, v.Nonce, v.CT, v.AD)
				if err != nil {
					t.Fatal(err)
				}
				want = v.PT
				if !bytes.Equal(got, want) {
					test.ReportError(t, got, want, cipher.name, v.Count)
				}
			}
		})
	}
}

func BenchmarkAscon(b *testing.B) {
	for _, cipher := range []struct {
		mode ascon.Mode
		name string
	}{
		{ascon.Ascon128, "ascon128"},
		{ascon.Ascon128a, "ascon128a"},
	} {
		for _, length := range []int{64, 1350, 8 * 1024} {
			b.Run(cipher.name+"/Open-"+strconv.Itoa(length), func(b *testing.B) { benchmarkOpen(b, make([]byte, length), cipher.mode) })
			b.Run(cipher.name+"/Seal-"+strconv.Itoa(length), func(b *testing.B) { benchmarkSeal(b, make([]byte, length), cipher.mode) })
		}
	}
}

func benchmarkSeal(b *testing.B, buf []byte, mode ascon.Mode) {
	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))

	var key [ascon.KeySize]byte
	var nonce [ascon.NonceSize]byte
	var ad [13]byte
	a, _ := ascon.New(key[:], mode)
	var out []byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = a.Seal(out[:0], nonce[:], buf, ad[:])
	}
}

func benchmarkOpen(b *testing.B, buf []byte, mode ascon.Mode) {
	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))

	var key [ascon.KeySize]byte
	var nonce [ascon.NonceSize]byte
	var ad [13]byte
	a, _ := ascon.New(key[:], mode)
	var out []byte

	ct := a.Seal(nil, nonce[:], buf, ad[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, _ = a.Open(out[:0], nonce[:], ct, ad[:])
	}
}
