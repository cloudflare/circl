// Code generated from pk_gen_vec.templ.go. DO NOT EDIT.

// The following code is translated from the C `vec` Additional Implementation
// from the NIST round 4 submission package.

package mceliece8192128f

import (
	"github.com/cloudflare/circl/kem/mceliece/internal"
)

const exponent = 128

func deBitSlicing(out *[1 << gfBits]uint64, in *[exponent][gfBits]uint64) {
	for i := 0; i < (1 << gfBits); i++ {
		out[i] = 0
	}

	for i := 0; i < exponent; i++ {
		for j := gfBits - 1; j >= 0; j-- {
			for r := 0; r < 64; r++ {
				out[i*64+r] <<= 1
				out[i*64+r] |= (in[i][j] >> r) & 1
			}
		}
	}
}

func toBitslicing2x(out0 *[exponent][gfBits]uint64, out1 *[exponent][gfBits]uint64, in *[1 << gfBits]uint64) {
	for i := 0; i < exponent; i++ {
		for j := gfBits - 1; j >= 0; j-- {
			for r := 63; r >= 0; r-- {
				out1[i][j] <<= 1
				out1[i][j] |= (in[i*64+r] >> (j + gfBits)) & 1
			}
		}

		for j := gfBits - 1; j >= 0; j-- {
			for r := 63; r >= 0; r-- {
				out0[i][gfBits-1-j] <<= 1
				out0[i][gfBits-1-j] |= (in[i*64+r] >> j) & 1
			}
		}
	}
}

func irrLoad(out *[2][gfBits]uint64, in []byte) {
	var (
		v0 uint64
		v1 uint64
	)
	irr := [sysT]uint16{}

	for i := 0; i < sysT; i++ {
		irr[i] = loadGf(in[i*2:])
	}

	for i := 0; i < gfBits; i++ {
		for j := 63; j >= 0; j-- {
			v0 <<= 1
			v1 <<= 1
			v0 |= uint64(irr[j]>>i) & 1
			v1 |= uint64(irr[j+64]>>i) & 1
		}

		out[0][i] = v0
		out[1][i] = v1
	}
}

// Return number of trailing zeros of the non-zero input `input`
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

// Takes two 16-bit integers and determines whether they are equal (all bits set) or different (0)
func sameMask64(x, y uint16) uint64 {
	mask := uint64(x ^ y)
	mask -= 1
	mask >>= 63
	mask = -mask
	return mask
}

// Move columns in matrix `mat`
func movColumns(mat *[pkNRows][(sysN + 63) / 64]uint64, pi []int16, pivots *uint64) bool {
	buf := [64]uint64{}
	ctzList := [32]uint64{}
	row := pkNRows - 32
	blockIdx := row / 64

	// extract the 32x64 matrix

	for i := 0; i < 32; i++ {
		buf[i] = (mat[row+i][blockIdx+0] >> 32) | (mat[row+i][blockIdx+1] << 32)
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

		t := (mat[i][blockIdx+0] >> 32) | (mat[i][blockIdx+1] << 32)

		for j := 0; j < 32; j++ {
			d := t >> j
			d ^= t >> ctzList[j]
			d &= 1

			t ^= d << ctzList[j]
			t ^= d << j
		}

		mat[i][blockIdx+0] = (mat[i][blockIdx+0] << 32 >> 32) | (t << 32)
		mat[i][blockIdx+1] = (mat[i][blockIdx+1] >> 32 << 32) | (t >> 32)

	}

	return true
}

// nolint:unparam
// Public key generation. Generate the public key `pk`,
// permutation `pi` and pivot element `pivots` based on the
// secret key `sk` and permutation `perm` provided.
// `pk` has `max(1 << GFBITS, SYS_N)` elements which is
// 4096 for mceliece348864 and 8192 for mceliece8192128.
// `sk` has `2 * SYS_T` elements and perm `1 << GFBITS`.
func pkGen(pk *[pkNRows * pkRowBytes]byte, irr []byte, perm *[1 << gfBits]uint32, pi *[1 << gfBits]int16, pivots *uint64) bool {
	const (
		nblocksH = (sysN + 63) / 64
		nblocksI = (pkNRows + 63) / 64

		blockIdx = nblocksI - 1
		tail     = pkNRows % 64
	)
	mat := [pkNRows][nblocksH]uint64{}
	var mask uint64

	irrInt := [2][gfBits]uint64{}

	consts := [exponent][gfBits]uint64{}
	eval := [exponent][gfBits]uint64{}
	prod := [exponent][gfBits]uint64{}
	tmp := [gfBits]uint64{}
	list := [1 << gfBits]uint64{}

	// compute the inverses
	irrLoad(&irrInt, irr)
	fft(&eval, &irrInt)
	vecCopy(&prod[0], &eval[0])
	for i := 1; i < exponent; i++ {
		vecMul(&prod[i], &prod[i-1], &eval[i])
	}
	vecInv(&tmp, &prod[exponent-1])
	for i := exponent - 2; i >= 0; i-- {
		vecMul(&prod[i+1], &prod[i], &tmp)
		vecMul(&tmp, &tmp, &eval[i+1])
	}
	vecCopy(&prod[0], &tmp)

	// fill matrix
	deBitSlicing(&list, &prod)
	for i := uint64(0); i < (1 << gfBits); i++ {
		list[i] <<= gfBits
		list[i] |= i
		list[i] |= (uint64(perm[i])) << 31
	}
	internal.UInt64Sort(list[:], 1<<gfBits)

	for i := 1; i < (1 << gfBits); i++ {
		if (list[i-1] >> 31) == (list[i] >> 31) {
			return false
		}
	}
	toBitslicing2x(&consts, &prod, &list)

	for i := 0; i < (1 << gfBits); i++ {
		pi[i] = int16(list[i] & gfMask)
	}

	for j := 0; j < nblocksH; j++ {
		for k := 0; k < gfBits; k++ {
			mat[k][j] = prod[j][k]
		}
	}

	for i := 1; i < sysT; i++ {
		for j := 0; j < nblocksH; j++ {
			vecMul(&prod[j], &prod[j], &consts[j])
			for k := 0; k < gfBits; k++ {
				mat[i*gfBits+k][j] = prod[j][k]
			}
		}
	}

	// gaussian elimination

	for i := 0; i < pkNRows/64; i++ {
		for j := 0; j < 64; j++ {
			row := i*64 + j

			if row == pkNRows-32 {
				if !movColumns(&mat, pi[:], pivots) {
					return false
				}
			}

			for k := row + 1; k < pkNRows; k++ {
				mask = mat[row][i] >> j
				mask &= 1
				mask -= 1

				for c := 0; c < nblocksH; c++ {
					mat[row][c] ^= mat[k][c] & mask
				}

			}
			// return if not systematic
			if ((mat[row][i] >> j) & 1) == 0 {
				return false
			}

			for k := 0; k < row; k++ {
				mask = mat[k][i] >> j
				mask &= 1
				mask = -mask

				for c := 0; c < nblocksH; c++ {
					mat[k][c] ^= mat[row][c] & mask
				}
			}

			for k := row + 1; k < pkNRows; k++ {
				mask = mat[k][i] >> j
				mask &= 1
				mask = -mask

				for c := 0; c < nblocksH; c++ {
					mat[k][c] ^= mat[row][c] & mask
				}
			}
		}
	}

	pkp := pk[:]

	for i := 0; i < pkNRows; i++ {
		for j := nblocksI; j < nblocksH; j++ {
			store8(pkp, mat[i][j])
			pkp = pkp[8:]
		}
	}

	return true
}
