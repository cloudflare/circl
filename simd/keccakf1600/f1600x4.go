// f1600x4 implements a fast fourway interleaved Keccak-f[1600] permutation on
// systems that support it.  Keccak-f[1600] is the permutation underlying
// Keccak, SHA3 and SHAKE.
//
// This parallel f[1600] is useful in a few niche applications: for instance,
// when computing many parallel SHAKE-128 hashes with same-length inputs such
// as is done in Dilithium or XMSS.
//
// Currently only amd64 systems with AVX2 are supported.  This package does
// not provide a generic implementation as it would be signficantly slower
// than using non-interleaved f[1600].  Check keccakf1600.AvailableX4 to see
// if the current system is supported.
package keccakf1600

import (
	"github.com/cloudflare/circl/internal/shake"
)

func genericF1600x4(a []uint64) {
	var buf [25]uint64
	for i := 0; i < 4; i++ {
		for j := 0; j < 25; j++ {
			buf[j] = a[4*j+i]
		}
		shake.KeccakF1600(&buf)
		for j := 0; j < 25; j++ {
			a[4*j+i] = buf[j]
		}
	}
}
