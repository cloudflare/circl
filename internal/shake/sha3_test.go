// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package shake

// Tests include all the ShortMsgKATs provided by the Keccak team at
// https://github.com/gvanas/KeccakCodePackage
//
// They only include the zero-bit case of the bitwise testvectors
// published by NIST in the draft of FIPS-202.

import (
	"bytes"
	"compress/flate"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"strings"
	"testing"
)

const (
	testString  = "brekeccakkeccak koax koax"
	katFilename = "testdata/keccakKats.json.deflate"
)

// decodeHex converts a hex-encoded string into a raw byte string.
func decodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// structs used to marshal JSON test-cases.
type KeccakKats struct {
	Kats map[string][]struct {
		Digest  string `json:"digest"`
		Length  int64  `json:"length"`
		Message string `json:"message"`

		// Defined only for cSHAKE
		N string `json:"N"`
		S string `json:"S"`
	}
}

// Run with "go test -race" on Go ≥1.14.
func TestIssue89(t *testing.T) {
	h := NewShake256()
	var buf [200]byte
	_, _ = h.Write(buf[1:])
}

// TestKeccakKats tests the SHA-3 and Shake implementations against all the
// ShortMsgKATs from https://github.com/gvanas/KeccakCodePackage
// (The testvectors are stored in keccakKats.json.deflate due to their length).
func TestKeccakKats(t *testing.T) {
	// Read the KATs.
	deflated, err := os.Open(katFilename)
	if err != nil {
		t.Errorf("error opening %s: %s", katFilename, err)
	}
	file := flate.NewReader(deflated)
	dec := json.NewDecoder(file)
	var katSet KeccakKats
	err = dec.Decode(&katSet)
	if err != nil {
		t.Errorf("error decoding KATs: %s", err)
	}

	for _, kat := range katSet.Kats["SHAKE256"] {
		d := NewShake256()
		in, err := hex.DecodeString(kat.Message)
		if err != nil {
			t.Errorf("error decoding KAT: %s", err)
		}

		_, _ = d.Write(in[:kat.Length/8])
		out := make([]byte, len(kat.Digest)/2)
		_, _ = d.Read(out)
		got := strings.ToUpper(hex.EncodeToString(out))
		if got != kat.Digest {
			t.Errorf("function=%s, length=%d N:%s\n S:%s\nmessage:\n %s \ngot:\n  %s\nwanted:\n %s",
				"SHAKE256", kat.Length, kat.N, kat.S, kat.Message, got, kat.Digest)
			t.Logf("wanted %+v", kat)
			t.FailNow()
		}
		continue
	}
}

// TestKeccak does a basic test of the non-standardized Keccak hash functions.
func TestKeccak(t *testing.T) {
	tests := []struct {
		fn   func() hash.Hash
		data []byte
		want string
	}{
		{
			NewLegacyKeccak256,
			[]byte("abc"),
			"4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
		},
	}

	for _, u := range tests {
		h := u.fn()
		_, _ = h.Write(u.data)
		got := h.Sum(nil)
		want := decodeHex(u.want)
		if !bytes.Equal(got, want) {
			t.Errorf("unexpected hash for size %d: got '%x' want '%s'", h.Size()*8, got, u.want)
		}
	}
}

// TestUnalignedWrite tests that writing data in an arbitrary pattern with
// small input buffers.
func TestUnalignedWrite(t *testing.T) {
	buf := sequentialBytes(0x10000)

	// Same for SHAKE
	want := make([]byte, 16)
	got := make([]byte, 16)
	d := NewShake256()

	d.Reset()
	_, _ = d.Write(buf)
	_, _ = d.Read(want)
	d.Reset()
	for i := 0; i < len(buf); {
		// Cycle through offsets which make a 137 byte sequence.
		// Because 137 is prime this sequence should exercise all corner cases.
		offsets := [17]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1}
		for _, j := range offsets {
			if v := len(buf) - i; v < j {
				j = v
			}
			_, _ = d.Write(buf[i : i+j])
			i += j
		}
	}
	_, _ = d.Read(got)
	if !bytes.Equal(got, want) {
		t.Errorf("Unaligned writes, alg=SHAKE256\ngot %q, want %q", got, want)
	}
}

// TestSqueezing checks that squeezing the full output a single time produces
// the same output as repeatedly squeezing the instance.
func TestSqueezing(t *testing.T) {
	d0 := NewShake256()
	_, _ = d0.Write([]byte(testString))
	ref := make([]byte, 32)
	_, _ = d0.Read(ref)

	d1 := NewShake256()
	_, _ = d1.Write([]byte(testString))
	multiple := make([]byte, 0, len(ref))
	for range ref {
		one := make([]byte, 1)
		_, _ = d1.Read(one)
		multiple = append(multiple, one...)
	}
	if !bytes.Equal(ref, multiple) {
		t.Errorf("SHAKE256 : squeezing %d bytes one at a time failed", len(ref))
	}
}

// sequentialBytes produces a buffer of size consecutive bytes 0x00, 0x01, ..., used for testing.
func sequentialBytes(size int) []byte {
	result := make([]byte, size)
	for i := range result {
		result[i] = byte(i)
	}
	return result
}

func TestReset(t *testing.T) {
	out1 := make([]byte, 32)
	out2 := make([]byte, 32)

	// Calculate hash for the first time
	c := NewShake256()
	_, _ = c.Write(sequentialBytes(0x100))
	_, _ = c.Read(out1)

	// Calculate hash again
	c.Reset()
	_, _ = c.Write(sequentialBytes(0x100))
	_, _ = c.Read(out2)

	if !bytes.Equal(out1, out2) {
		t.Error("\nExpected:\n", out1, "\ngot:\n", out2)
	}
}

func TestClone(t *testing.T) {
	out1 := make([]byte, 16)
	out2 := make([]byte, 16)
	in := sequentialBytes(0x100)

	h1 := NewShake256()
	_, _ = h1.Write([]byte{0x01})

	h2 := h1.Clone()

	_, _ = h1.Write(in)
	_, _ = h1.Read(out1)

	_, _ = h2.Write(in)
	_, _ = h2.Read(out2)
	if !bytes.Equal(out1, out2) {
		t.Error("\nExpected:\n", hex.EncodeToString(out1), "\ngot:\n", hex.EncodeToString(out2))
	}
}

// Checks wether reset works correctly after clone.
func TestCloneAndReset(t *testing.T) {
	// Shake 256, uses SHA-3 with rate = 136
	d1 := NewShake256()
	buf1 := make([]byte, 28)
	buf2 := make([]byte, 28)
	_, _ = d1.Write([]byte{0xcc})
	// Reading x bytes where x<168-136. This makes capability
	// of the state buffer shorter.
	_, _ = d1.Read(buf1)
	// This will crash if sha-3 code uses cap() instead
	// of len() when calculating length of state buffer
	d2 := d1.Clone()
	d2.Reset()
	_, _ = d2.Write([]byte{0xcc})
	_, _ = d2.Read(buf2)

	if !bytes.Equal(buf1, buf2) {
		t.Error("Different value when reading after reset")
	}
}

// BenchmarkPermutationFunction measures the speed of the permutation function
// with no input data.
func BenchmarkPermutationFunction(b *testing.B) {
	b.SetBytes(int64(200))
	var lanes [25]uint64
	for i := 0; i < b.N; i++ {
		KeccakF1600(&lanes)
	}
}

// benchmarkShake is specialized to the Shake instances, which don't
// require a copy on reading output.
func benchmarkShake(b *testing.B, h Shake, size, num int) {
	b.StopTimer()
	h.Reset()
	data := sequentialBytes(size)
	var d [32]byte

	b.SetBytes(int64(size * num))
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		h.Reset()
		for j := 0; j < num; j++ {
			_, _ = h.Write(data)
		}
		_, _ = h.Read(d[:])
	}
}

func BenchmarkShake256_MTU(b *testing.B)  { benchmarkShake(b, NewShake256(), 1350, 1) }
func BenchmarkShake256_16x(b *testing.B)  { benchmarkShake(b, NewShake256(), 16, 1024) }
func BenchmarkShake256_1MiB(b *testing.B) { benchmarkShake(b, NewShake256(), 1024, 1024) }
func BenchmarkCShake256_448_16x(b *testing.B) {
	benchmarkShake(b, NewShake256(), 448, 16)
}
func BenchmarkCShake256_1MiB(b *testing.B) {
	benchmarkShake(b, NewShake256(), 1024, 1024)
}

func Example_sum() {
	buf := []byte("some data to hash")
	// A hash needs to be 64 bytes long to have 256-bit collision resistance.
	h := make([]byte, 64)
	// Compute a 64-byte hash of buf and put it in h.
	shake := NewShake256()
	_, _ = shake.Write(buf)
	_, _ = shake.Read(h)
	fmt.Printf("%x\n", h)
	// Output: 0f65fe41fc353e52c55667bb9e2b27bfcc8476f2c413e9437d272ee3194a4e3146d05ec04a25d16b8f577c19b82d16b1424c3e022e783d2b4da98de3658d363d
}

func Example_mac() {
	k := []byte("this is a secret key; you should generate a strong random key that's at least 32 bytes long")
	buf := []byte("and this is some data to authenticate")
	// A MAC with 32 bytes of output has 256-bit security strength -- if you use at least a 32-byte-long key.
	h := make([]byte, 32)
	d := NewShake256()
	// Write the key into the hash.
	_, _ = d.Write(k)
	// Now write the data.
	_, _ = d.Write(buf)
	// Read 32 bytes of output from the hash into h.
	_, _ = d.Read(h)
	fmt.Printf("%x\n", h)
	// Output: 78de2974bd2711d5549ffd32b753ef0f5fa80a0db2556db60f0987eb8a9218ff
}

func ExampleShake() {
	out := make([]byte, 32)
	msg := []byte("The quick brown fox jumps over the lazy dog")

	// Example 1: Simple Shake
	c1 := NewShake256()
	_, _ = c1.Write(msg)
	_, _ = c1.Read(out)
	fmt.Println(hex.EncodeToString(out))

	// Output:
	//2f671343d9b2e1604dc9dcf0753e5fe15c7c64a0d283cbbf722d411a0e36f6ca
}
