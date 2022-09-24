// Code generated from pk_gen.templ.go. DO NOT EDIT.

package mceliece348864f

import (
	"github.com/cloudflare/circl/kem/mceliece/internal"
	"github.com/cloudflare/circl/math/gf4096"
)

func ctz(in uint64) int {
	m := 0
	r := 0
	for i := 0; i < 64; i++ {
		b := int((in >> i) & 1)
		m |= b
		r += (m ^ 1) & (b ^ 1)
	}
	return r
}

func sameMask64(x, y uint16) uint64 {
	mask := uint64(x ^ y)
	mask -= 1
	mask >>= 63
	mask = -mask
	return mask
}

func movColumns(mat *[pkNRows][sysN / 8]byte, pi []int16, pivots *uint64) bool {
	buf := [64]uint64{}
	ctzList := [32]uint64{}
	row := pkNRows - 32
	blockIdx := row / 8

	// extract the 32x64 matrix

	for i := 0; i < 32; i++ {
		buf[i] = load8(mat[row+i][blockIdx:])
	}

	// compute the column indices of pivots by Gaussian elimination.
	// the indices are stored in ctz_list

	*pivots = 0

	for i := 0; i < 32; i++ {
		t := buf[i]
		for j := i + 1; j < 32; j++ {
			t |= buf[j]
		}
		if t == 0 {
			return false // return if buf is not full rank
		}
		s := ctz(t)
		ctzList[i] = uint64(s)
		*pivots |= 1 << s

		for j := i + 1; j < 32; j++ {
			mask := (buf[i] >> s) & 1
			mask -= 1
			buf[i] ^= buf[j] & mask
		}
		for j := i + 1; j < 32; j++ {
			mask := (buf[j] >> s) & 1
			mask = -mask
			buf[j] ^= buf[i] & mask
		}
	}

	// updating permutation
	for j := 0; j < 32; j++ {
		for k := j + 1; k < 64; k++ {
			d := uint64(pi[row+j] ^ pi[row+k])
			d &= sameMask64(uint16(k), uint16(ctzList[j]))
			pi[row+j] ^= int16(d)
			pi[row+k] ^= int16(d)
		}
	}

	// moving columns of mat according to the column indices of pivots
	for i := 0; i < pkNRows; i++ {

		t := load8(mat[i][blockIdx:])

		for j := 0; j < 32; j++ {
			d := t >> j
			d ^= t >> ctzList[j]
			d &= 1

			t ^= d << ctzList[j]
			t ^= d << j
		}

		store8(mat[i][blockIdx:], t)

	}

	return true
}

// nolint:unparam
func pkGen(pk *[pkNRows * pkRowBytes]byte, sk []byte, perm *[1 << gfBits]uint32, pi *[1 << gfBits]int16, pivots *uint64) bool {
	buf := [1 << gfBits]uint64{}
	mat := [pkNRows][sysN / 8]byte{}
	g := [sysT + 1]gf{}
	L := [sysN]gf{}
	inv := [sysN]gf{}

	g[sysT] = 1
	for i := 0; i < sysT; i++ {
		g[i] = loadGf(sk)
		sk = sk[2:]
	}

	for i := 0; i < 1<<gfBits; i++ {
		buf[i] = uint64(perm[i])
		buf[i] <<= 31
		buf[i] |= uint64(i)
	}

	internal.UInt64Sort(buf[:], 1<<gfBits)

	for i := 1; i < (1 << gfBits); i++ {
		if (buf[i-1] >> 31) == (buf[i] >> 31) {
			return false
		}
	}

	for i := 0; i < (1 << gfBits); i++ {
		pi[i] = int16(buf[i] & gfMask)
	}

	for i := 0; i < sysN; i++ {
		L[i] = bitRev(gf(pi[i]))
	}

	// filling the matrix
	root(&inv, &g, &L)

	for i := 0; i < sysN; i++ {
		inv[i] = gf4096.Inv(inv[i])
	}

	for i := 0; i < sysT; i++ {
		for j := 0; j < sysN; j += 8 {
			for k := 0; k < gfBits; k++ {
				b := byte(inv[j+7]>>k) & 1
				b <<= 1
				b |= byte(inv[j+6]>>k) & 1
				b <<= 1
				b |= byte(inv[j+5]>>k) & 1
				b <<= 1
				b |= byte(inv[j+4]>>k) & 1
				b <<= 1
				b |= byte(inv[j+3]>>k) & 1
				b <<= 1
				b |= byte(inv[j+2]>>k) & 1
				b <<= 1
				b |= byte(inv[j+1]>>k) & 1
				b <<= 1
				b |= byte(inv[j+0]>>k) & 1

				mat[i*gfBits+k][j/8] = b
			}
		}

		for j := 0; j < sysN; j++ {
			inv[j] = gf4096.Mul(inv[j], L[j])
		}
	}

	// gaussian elimination
	for i := 0; i < (pkNRows+7)/8; i++ {
		for j := 0; j < 8; j++ {
			row := i*8 + j

			if row >= pkNRows {
				break
			}

			if row == pkNRows-32 {
				if !movColumns(&mat, pi[:], pivots) {
					return false
				}
			}

			for k := row + 1; k < pkNRows; k++ {
				mask := mat[row][i] ^ mat[k][i]
				mask >>= j
				mask &= 1
				mask = -mask

				for c := 0; c < sysN/8; c++ {
					mat[row][c] ^= mat[k][c] & mask
				}
			}

			// return if not systematic
			if ((mat[row][i] >> j) & 1) == 0 {
				return false
			}

			for k := 0; k < pkNRows; k++ {
				if k != row {
					mask := mat[k][i] >> j
					mask &= 1
					mask = -mask

					for c := 0; c < sysN/8; c++ {
						mat[k][c] ^= mat[row][c] & mask
					}
				}
			}
		}
	}

	for i := 0; i < pkNRows; i++ {
		copy(pk[i*pkRowBytes:], mat[i][pkNRows/8:pkNRows/8+pkRowBytes])
	}

	return true
}
