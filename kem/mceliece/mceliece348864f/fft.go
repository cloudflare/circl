// Code generated from fft_348864.templ.go. DO NOT EDIT.

// The following code is translated from the C `vec` Additional Implementation
// from the NIST round 4 submission package.

package mceliece348864f

import "github.com/cloudflare/circl/kem/mceliece/internal"

func fft(out *[exponent][gfBits]uint64, in *[gfBits]uint64) {
	radixConversions(in)
	butterflies(out, in)
}

func radixConversions(in *[gfBits]uint64) {
	for j := 0; j <= 4; j++ {
		for i := 0; i < gfBits; i++ {
			for k := 4; k >= j; k-- {
				in[i] ^= (in[i] & internal.RadixConversionsMask[k][0]) >> (1 << k)
				in[i] ^= (in[i] & internal.RadixConversionsMask[k][1]) >> (1 << k)
			}
		}

		vecMul(in, in, &internal.RadixConversionsS4096[j]) // scaling
	}
}

func butterflies(out *[exponent][gfBits]uint64, in *[gfBits]uint64) {
	tmp := [gfBits]uint64{}
	var constsPtr int
	// broadcast
	for j := 0; j < 64; j++ {
		for i := 0; i < gfBits; i++ {
			out[j][i] = (in[i] >> internal.ButterfliesReversal4096[j]) & 1
			out[j][i] = -out[j][i]
		}
	}

	// butterflies
	for i := 0; i <= 5; i++ {
		s := 1 << i

		for j := 0; j < 64; j += 2 * s {
			for k := j; k < j+s; k++ {
				vecMul(&tmp, &out[k+s], &internal.ButterfliesConsts4096[constsPtr+(k-j)])

				for b := 0; b < gfBits; b++ {
					out[k][b] ^= tmp[b]
				}
				for b := 0; b < gfBits; b++ {
					out[k+s][b] ^= out[k][b]
				}
			}
		}

		constsPtr += 1 << i
	}

	// adding the part contributed by x^64
	for i := 0; i < 64; i++ {
		for b := 0; b < gfBits; b++ {
			out[i][b] ^= internal.Powers4096[i][b]
		}
	}
}
