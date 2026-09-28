//go:build amd64 && !purego
// +build amd64,!purego

package matops

import "golang.org/x/sys/cpu"

var (
	hasAVX512 = cpu.X86.HasAVX512F && cpu.X86.HasAVX512BW
	hasAVX2   = cpu.X86.HasAVX2
)

// AddMasked sets dst[i] ^= src[i] & mask for every byte in the shorter of dst
// and src. It runs in time independent of mask and of the buffer contents.
//
// The widest supported kernel handles the aligned bulk of the buffer and a
// word-wise generic tail finishes the remainder: AVX-512 (64-byte blocks) is
// preferred, then AVX2 (32-byte blocks), then the pure-Go fallback.
func AddMasked(dst, src []byte, mask byte) {
	n := len(dst)
	if len(src) < n {
		n = len(src)
	}
	switch {
	case hasAVX512:
		block := n &^ 63
		if block > 0 {
			addMaskedAVX512(&dst[0], &src[0], block, mask)
		}
		if block < n {
			addMaskedGeneric(dst[block:n], src[block:n], mask)
		}
	case hasAVX2:
		block := n &^ 31
		if block > 0 {
			addMaskedAVX2(&dst[0], &src[0], block, mask)
		}
		if block < n {
			addMaskedGeneric(dst[block:n], src[block:n], mask)
		}
	default:
		addMaskedGeneric(dst[:n], src[:n], mask)
	}
}
