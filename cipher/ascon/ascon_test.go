package ascon_test

import (
	"bytes"
	"crypto/cipher"
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
	for _, mode := range []ascon.Mode{ascon.Ascon128, ascon.Ascon128a} {
		name := mode.String()
		t.Run(name, func(t *testing.T) {
			vectors := readFile(t, "testdata/"+name+".json")
			for _, v := range vectors {
				a, err := ascon.New(v.Key, mode)
				test.CheckNoErr(t, err, "failed to create cipher")

				var aead cipher.AEAD = a
				test.CheckOk(len(v.Nonce) == aead.NonceSize(), "bad nonce size", t)
				got := aead.Seal(nil, v.Nonce, v.PT, v.AD)
				want := v.CT
				if !bytes.Equal(got, want) {
					test.ReportError(t, got, want, name, v.Count)
				}

				got, err = aead.Open(nil, v.Nonce, v.CT, v.AD)
				if err != nil {
					t.Fatal(err)
				}
				want = v.PT
				if !bytes.Equal(got, want) {
					test.ReportError(t, got, want, name, v.Count)
				}
				test.CheckOk(len(v.PT)+aead.Overhead() == len(v.CT), "bad overhead size", t)
			}
		})
	}
}

func TestBadInputs(t *testing.T) {
	var key [ascon.KeySize]byte
	var m ascon.Mode = 0

	_, err := ascon.New(key[:], m)
	test.CheckIsErr(t, err, "should fail due to bad mode")

	err = test.CheckPanic(func() { _ = m.String() })
	test.CheckNoErr(t, err, "should panic due to bad mode")

	_, err = ascon.New(nil, ascon.Ascon128)
	test.CheckIsErr(t, err, "should fail due to nil key")

	_, err = ascon.New(key[:4], ascon.Ascon128)
	test.CheckIsErr(t, err, "should fail due to short key")

	a, _ := ascon.New(key[:], ascon.Ascon128)
	err = test.CheckPanic(func() { _ = a.Seal(nil, nil, nil, nil) })
	test.CheckNoErr(t, err, "should panic due to bad nonce")

	err = test.CheckPanic(func() { _, _ = a.Open(nil, nil, nil, nil) })
	test.CheckNoErr(t, err, "should panic due to bad nonce")

	var nonce [ascon.NonceSize]byte
	_ = a.Seal(nil, nonce[:], nil, nil)
	_, err = a.Open(nil, nonce[:], nil, nil)
	test.CheckIsErr(t, err, "should panic due to empty ciphertext")

	pt := []byte("")
	ct := a.Seal(nil, nonce[:], pt, nil)
	ct[0] ^= 0xFF // tamper ciphertext
	_, err = a.Open(nil, nonce[:], ct, nil)
	test.CheckIsErr(t, err, "should panic due to bad ciphertext")
}

func BenchmarkAscon(b *testing.B) {
	for _, mode := range []ascon.Mode{ascon.Ascon128, ascon.Ascon128a} {
		for _, length := range []int{64, 1350, 8 * 1024} {
			b.Run(mode.String()+"/Open-"+strconv.Itoa(length), func(b *testing.B) { benchmarkOpen(b, make([]byte, length), mode) })
			b.Run(mode.String()+"/Seal-"+strconv.Itoa(length), func(b *testing.B) { benchmarkSeal(b, make([]byte, length), mode) })
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
