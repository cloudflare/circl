// Package matops provides the constant-time matrix primitive used by the
// Classic McEliece key generator.
//
// The Gaussian elimination in pkGen dominates key-generation time and repeats
// a single masked row addition over GF(2): dst[i] ^= src[i] & mask, where mask
// is the all-zero or all-one byte selected from secret pivot bits. AddMasked is
// accelerated with AVX-512 (preferred) or AVX2 on amd64 and falls back to a
// word-wise pure-Go implementation elsewhere and under the purego build tag.
//
// Every code path processes the full buffer and derives the per-byte mask
// arithmetically, so the running time is independent of the mask value and of
// the buffer contents. This preserves the constant-time behaviour required when
// operating on secret key material.
package matops

import "encoding/binary"

// addMaskedGeneric computes dst[i] ^= src[i] & mask for every byte of the
// shorter of dst and src, processing eight bytes per iteration. The mask byte is
// broadcast to all lanes with a multiply so the routine never branches on the
// (secret) mask value.
func addMaskedGeneric(dst, src []byte, mask byte) {
	n := len(dst)
	if len(src) < n {
		n = len(src)
	}
	m := uint64(mask) * 0x0101010101010101
	i := 0
	for ; i+8 <= n; i += 8 {
		d := binary.LittleEndian.Uint64(dst[i:])
		s := binary.LittleEndian.Uint64(src[i:])
		binary.LittleEndian.PutUint64(dst[i:], d^(s&m))
	}
	for ; i < n; i++ {
		dst[i] ^= src[i] & mask
	}
}
