package matops

import (
	"bytes"
	"math/rand"
	"testing"
)

func refAddMasked(dst, src []byte, mask byte) {
	n := len(dst)
	if len(src) < n {
		n = len(src)
	}
	for i := 0; i < n; i++ {
		dst[i] ^= src[i] & mask
	}
}

var testLengths = []int{0, 1, 7, 8, 15, 31, 32, 33, 63, 64, 65, 127, 436, 870, 1024, 1025}

var testMasks = []byte{0x00, 0x01, 0x5a, 0xff}

func TestAddMasked(t *testing.T) {
	rng := rand.New(rand.NewSource(1)) // nolint:gosec // deterministic test vectors
	for _, n := range testLengths {
		for _, mask := range testMasks {
			a := make([]byte, n)
			b := make([]byte, n)
			_, _ = rng.Read(a)
			_, _ = rng.Read(b)

			want := append([]byte(nil), a...)
			refAddMasked(want, b, mask)

			got := append([]byte(nil), a...)
			AddMasked(got, b, mask)

			if !bytes.Equal(got, want) {
				t.Fatalf("AddMasked n=%d mask=%#02x mismatch", n, mask)
			}
		}
	}
}

func TestAddMaskedGeneric(t *testing.T) {
	rng := rand.New(rand.NewSource(2)) // nolint:gosec // deterministic test vectors
	for _, n := range testLengths {
		for _, mask := range testMasks {
			a := make([]byte, n)
			b := make([]byte, n)
			_, _ = rng.Read(a)
			_, _ = rng.Read(b)

			want := append([]byte(nil), a...)
			refAddMasked(want, b, mask)

			got := append([]byte(nil), a...)
			addMaskedGeneric(got, b, mask)

			if !bytes.Equal(got, want) {
				t.Fatalf("addMaskedGeneric n=%d mask=%#02x mismatch", n, mask)
			}
		}
	}
}
