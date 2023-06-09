// Code generated from vec.templ.go. DO NOT EDIT.

// The following code is translated from the C `vec` Additional Implementation
// from the NIST round 4 submission package.

package mceliece460896

func vecMul(h, f, g *[gfBits]uint64) {
	buf := [2*gfBits - 1]uint64{}

	for i := 0; i < 2*gfBits-1; i++ {
		buf[i] = 0
	}

	for i := 0; i < gfBits; i++ {
		for j := 0; j < gfBits; j++ {
			buf[i+j] ^= f[i] & g[j]
		}
	}

	for i := 2*gfBits - 2; i >= gfBits; i-- {

		buf[i-gfBits+4] ^= buf[i]
		buf[i-gfBits+3] ^= buf[i]
		buf[i-gfBits+1] ^= buf[i]
		buf[i-gfBits+0] ^= buf[i]

	}

	for i := 0; i < gfBits; i++ {
		h[i] = buf[i]
	}
}

// bitsliced field squarings
func vecSq(out, in *[gfBits]uint64) {
	result := [gfBits]uint64{}

	t := in[11] ^ in[12]

	result[0] = in[0] ^ in[11]
	result[1] = in[7] ^ t
	result[2] = in[1] ^ in[7]
	result[3] = in[8] ^ t
	result[4] = in[2] ^ in[7]
	result[4] = result[4] ^ in[8]
	result[4] = result[4] ^ t
	result[5] = in[7] ^ in[9]
	result[6] = in[3] ^ in[8]
	result[6] = result[6] ^ in[9]
	result[6] = result[6] ^ in[12]
	result[7] = in[8] ^ in[10]
	result[8] = in[4] ^ in[9]
	result[8] = result[8] ^ in[10]
	result[9] = in[9] ^ in[11]
	result[10] = in[5] ^ in[10]
	result[10] = result[10] ^ in[11]
	result[11] = in[10] ^ in[12]
	result[12] = in[6] ^ t

	for i := 0; i < gfBits; i++ {
		out[i] = result[i]
	}
}

// bitsliced field inverses
func vecInv(out, in *[gfBits]uint64) {
	tmp11 := [gfBits]uint64{}
	tmp1111 := [gfBits]uint64{}

	vecCopy(out, in)

	vecSq(out, out)
	vecMul(&tmp11, out, in) // ^11

	vecSq(out, &tmp11)
	vecSq(out, out)
	vecMul(&tmp1111, out, &tmp11) // ^1111

	vecSq(out, &tmp1111)
	vecSq(out, out)
	vecSq(out, out)
	vecSq(out, out)
	vecMul(out, out, &tmp1111) // ^11111111

	vecSq(out, out)
	vecSq(out, out)
	vecSq(out, out)
	vecSq(out, out)
	vecMul(out, out, &tmp1111) // ^111111111111

	vecSq(out, out) // ^1111111111110
}

func vecSetBits(b uint64) uint64 {
	ret := -b
	return ret
}

func vecSet116b(v uint16) uint64 {
	ret := uint64(v)
	ret |= ret << 16
	ret |= ret << 32

	return ret
}

func vecCopy(out, in *[gfBits]uint64) {
	for i := 0; i < gfBits; i++ {
		out[i] = in[i]
	}
}

func vecOrReduce(a *[gfBits]uint64) uint64 {
	ret := a[0]
	for i := 1; i < gfBits; i++ {
		ret |= a[i]
	}

	return ret
}

func vecTestZ(a uint64) int {
	a |= a >> 32
	a |= a >> 16
	a |= a >> 8
	a |= a >> 4
	a |= a >> 2
	a |= a >> 1

	return int((a & 1) ^ 1)
}
