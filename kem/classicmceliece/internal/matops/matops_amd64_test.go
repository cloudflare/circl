//go:build amd64 && !purego
// +build amd64,!purego

package matops

import (
	"bytes"
	"math/rand"
	"testing"
)

// testKernel drives one asm kernel directly (bypassing feature dispatch) so
// both the AVX-512 and AVX2 paths are exercised even on a host that would only
// select the widest one. block is the kernel's required length multiple.
func testKernel(t *testing.T, name string, block int, fn func(dst, src *byte, n int, mask byte)) {
	t.Helper()
	rng := rand.New(rand.NewSource(3)) // nolint:gosec // deterministic test vectors
	for _, blocks := range []int{1, 2, 3, 7, 16} {
		n := block * blocks
		for _, mask := range testMasks {
			a := make([]byte, n)
			b := make([]byte, n)
			_, _ = rng.Read(a)
			_, _ = rng.Read(b)

			want := append([]byte(nil), a...)
			refAddMasked(want, b, mask)

			got := append([]byte(nil), a...)
			fn(&got[0], &b[0], n, mask)

			if !bytes.Equal(got, want) {
				t.Fatalf("%s n=%d mask=%#02x mismatch", name, n, mask)
			}
		}
	}
}

func TestAddMaskedAVX2Kernel(t *testing.T) {
	if !hasAVX2 {
		t.Skip("AVX2 not available")
	}
	testKernel(t, "addMaskedAVX2", 32, addMaskedAVX2)
}

func TestAddMaskedAVX512Kernel(t *testing.T) {
	if !hasAVX512 {
		t.Skip("AVX-512 not available")
	}
	testKernel(t, "addMaskedAVX512", 64, addMaskedAVX512)
}
