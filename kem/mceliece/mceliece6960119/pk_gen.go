// Code generated from pk_gen.templ.go. DO NOT EDIT.

package mceliece6960119

import (
	"github.com/cloudflare/circl/kem/mceliece/internal"
	"github.com/cloudflare/circl/math/gf8192"
)

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
		inv[i] = gf8192.Inv(inv[i])
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
			inv[j] = gf8192.Mul(inv[j], L[j])
		}
	}

	// gaussian elimination
	for i := 0; i < (pkNRows+7)/8; i++ {
		for j := 0; j < 8; j++ {
			row := i*8 + j

			if row >= pkNRows {
				break
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

	tail := pkNRows % 8
	const innerPkAccesses = ((sysN/8 - 1) - (pkNRows-1)/8) + 1
	for i := 0; i < pkNRows; i++ {
		idx := 0
		for j := (pkNRows - 1) / 8; j < sysN/8-1; j++ {
			pk[i*innerPkAccesses+idx] = (mat[i][j] >> tail) | (mat[i][j+1] << (8 - tail))
			idx++
		}
		pk[(i+1)*innerPkAccesses-1] = mat[i][sysN/8-1] >> tail
	}

	return true
}
