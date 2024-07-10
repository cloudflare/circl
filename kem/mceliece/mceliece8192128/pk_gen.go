// Code generated from pk_gen_vec.templ.go. DO NOT EDIT.

// The following code is translated from the C `vec` Additional Implementation
// from the NIST round 4 submission package.

package mceliece8192128

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

	ops := [pkNRows][nblocksI]uint64{}

	oneRow := [pkNCols / 64]uint64{}

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

	for j := 0; j < nblocksI; j++ {
		for k := 0; k < gfBits; k++ {
			mat[k][j] = prod[j][k]
		}
	}

	for i := 1; i < sysT; i++ {
		for j := 0; j < nblocksI; j++ {
			vecMul(&prod[j], &prod[j], &consts[j])
			for k := 0; k < gfBits; k++ {
				mat[i*gfBits+k][j] = prod[j][k]
			}
		}
	}

	// gaussian elimination to obtain an upper triangular matrix
	// and keep track of the operations in ops

	for i := 0; i < pkNRows/64; i++ {
		for j := 0; j < 64; j++ {
			row := i*64 + j
			for c := 0; c < pkNRows/64; c++ {
				ops[row][c] = 0
			}
		}
	}
	for i := 0; i < pkNRows/64; i++ {
		for j := 0; j < 64; j++ {
			row := i*64 + j
			ops[row][i] = 1
			ops[row][i] <<= j
		}
	}

	for i := 0; i < pkNRows/64; i++ {
		for j := 0; j < 64; j++ {
			row := i*64 + j

			for k := row + 1; k < pkNRows; k++ {
				mask = mat[row][i] >> j
				mask &= 1
				mask -= 1

				for c := 0; c < nblocksI; c++ {
					mat[row][c] ^= mat[k][c] & mask
					ops[row][c] ^= ops[k][c] & mask
				}

			}
			// return if not systematic
			if ((mat[row][i] >> j) & 1) == 0 {
				return false
			}

			for k := row + 1; k < pkNRows; k++ {
				mask = mat[k][i] >> j
				mask &= 1
				mask = -mask

				for c := 0; c < nblocksI; c++ {
					mat[k][c] ^= mat[row][c] & mask

					ops[k][c] ^= ops[row][c] & mask

				}
			}
		}
	}

	pkp := pk[:]

	// computing the lineaer map required to obatin the systematic form

	for i := pkNRows/64 - 1; i >= 0; i-- {
		for j := 63; j >= 0; j-- {
			row := i*64 + j
			for k := 0; k < row; k++ {
				mask = mat[k][i] >> j
				mask &= 1
				mask = -mask

				for c := 0; c < pkNRows/64; c++ {
					ops[k][c] ^= ops[row][c] & mask
				}
			}
		}
	}

	// apply the linear map to the non-systematic part
	for j := nblocksI; j < nblocksH; j++ {
		for k := 0; k < gfBits; k++ {
			mat[k][j] = prod[j][k]
		}
	}

	for i := 1; i < sysT; i++ {
		for j := nblocksI; j < nblocksH; j++ {
			vecMul(&prod[j], &prod[j], &consts[j])
			for k := 0; k < gfBits; k++ {
				mat[i*gfBits+k][j] = prod[j][k]
			}
		}
	}

	for i := 0; i < pkNRows/64; i++ {
		for j := 0; j < 64; j++ {
			row := i*64 + j

			for k := 0; k < pkNCols/64; k++ {
				oneRow[k] = 0
			}

			for c := 0; c < pkNRows/64; c++ {
				for d := 0; d < 64; d++ {
					mask = ops[row][c] >> d
					mask &= 1
					mask = -mask

					for k := 0; k < pkNCols/64; k++ {
						oneRow[k] ^= mat[c*64+d][k+pkNRows/64] & mask
					}
				}
			}

			for k := 0; k < pkNCols/64; k++ {
				store8(pkp, oneRow[k])
				pkp = pkp[8:]
			}
		}
	}

	return true
}
