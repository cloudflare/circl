//go:build !amd64 || purego
// +build !amd64 purego

package matops

// AddMasked sets dst[i] ^= src[i] & mask for every byte in the shorter of dst
// and src. It runs in time independent of mask and of the buffer contents.
func AddMasked(dst, src []byte, mask byte) {
	addMaskedGeneric(dst, src, mask)
}
