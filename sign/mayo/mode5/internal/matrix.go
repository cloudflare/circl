// Code generated from mode1/internal/matrix.go by gen.go

package internal

// Given b in GF(16), packs the 32-bit result of (b*x^3, b*x^2, b*x, b) into the returned multiplication table.
func mulTable(b uint8) uint32 {
	x := uint32(b) * 0x08040201
	highNibble := x & uint32(0xf0f0f0f0)

	// mod x^4+x+1
	return (x ^ (highNibble >> 4) ^ (highNibble >> 3))
}

func vecMulAddPackedTab(p int, in []uint64, tab uint32, acc []uint64) {
	lsbMask := uint64(0x1111111111111111)
	for i := 0; i < p; i++ {
		acc[i] ^= (in[i]&lsbMask)*uint64(tab&0xff) ^
			((in[i]>>1)&lsbMask)*uint64((tab>>8)&0xf) ^
			((in[i]>>2)&lsbMask)*uint64((tab>>16)&0xf) ^
			((in[i]>>3)&lsbMask)*uint64((tab>>24)&0xf)
	}
}

func vecMulAddPacked(p int, in []uint64, a byte, acc []uint64) {
	tab := mulTable(a)
	vecMulAddPackedTab(p, in, tab, acc)
}

// Multiplies each nibble in a by b.
func mulAddPacked(a uint64, b uint8) uint64 {
	msb := uint64(0x8888888888888888)
	a64 := a
	r64 := a64 * uint64(b&1)

	for i := 1; i < 4; i++ {
		b >>= 1
		aMsb := a64 & msb
		a64 ^= aMsb
		a64 = (a64 << 1) ^ ((aMsb >> 3) * 3)
		r64 ^= (a64) * uint64(b&1)
	}

	return r64
}

// acc += M1*M2
// acc and M2 are multiple matrices, M1 is a single matrix
func mulAddMatXMMat(acc []uint64, m1 []uint8, m2 []uint64, rows int, cols int, cols2 int) {
	for r := 0; r < rows; r++ {
		for c := 0; c < cols; c++ {
			tab := mulTable(m1[r*cols+c])
			for k := 0; k < cols2; k++ {
				// The following multiplication table way is equivalent to:
				// for p := 0; p < P; p++ {
				// 	acc[P*(r*cols2+k)+p] ^= gf16v_mul_u64(m2[P*(c*cols2+k)+p], m1[r*cols+c])
				// }
				vecMulAddPackedTab(P, m2[P*(c*cols2+k):], tab, acc[P*(r*cols2+k):])
			}
		}
	}
}

// acc += M1*M2, where M1 is upper triangular, acc and M2 is not
// acc and M1 are multiple matrices, M2 is a single matrix
func mulAddMUpperTriangularMatXMat(acc []uint64, m1 []uint64, m2 []uint8, rows int, cols2 int) {
	// The ordinary summation order is r -> c -> k, but here it is interchanged to make use of multiplication table
	cols := rows
	for k := 0; k < cols2; k++ {
		for c := 0; c < cols; c++ {
			tab := mulTable(m2[c*cols2+k])
			for r := 0; r <= c; r++ {
				pos := r*(cols*2-r+1)/2 + (c - r)
				vecMulAddPackedTab(P, m1[P*pos:], tab, acc[P*(r*cols2+k):])
			}
		}
	}
}

// acc += M1^T*M2,
// acc and M2 are multiple matrices, M1 is a single matrix
// M1, before ^T, is of rows x cols
func mulAddMatTransXMMat(acc []uint64, m1 []uint8, m2 []uint64, rows int, cols int, cols2 int) {
	for r := 0; r < cols; r++ {
		for c := 0; c < rows; c++ {
			tab := mulTable(m1[c*cols+r])
			for k := 0; k < cols2; k++ {
				vecMulAddPackedTab(P, m2[P*(c*cols2+k):], tab, acc[P*(r*cols2+k):])
			}
		}
	}
}

// acc += M1*M2^T,
// acc and M1 are multiple matrices, M2 is a single matrix
// M2, before ^T, is of cols2 x cols, but cols strides at colsStride
// M1 optionally upper triangular
func mulAddMMatXMatTrans(acc []uint64, m1 []uint64, m2 []uint8, rows int, cols int, cols2 int, colsStride int, isM1Triangular bool) {
	for k := 0; k < cols2; k++ {
		for c := 0; c < cols; c++ {
			rBound := rows - 1
			if isM1Triangular {
				rBound = c
			}
			for r := 0; r <= rBound; r++ {
				tab := mulTable(m2[k*colsStride+c])
				pos := r*cols + c
				if isM1Triangular {
					pos = r*(cols*2-r+1)/2 + (c - r)
				}
				vecMulAddPackedTab(P, m1[P*pos:], tab, acc[P*(r*cols2+k):])
			}
		}
	}
}

// acc += (M1+M1^T)*M2
// M1 of rows x rows is upper triangular; M2 is of rows x cols2
// acc and M1 are multiple matrices, M2 is a single matrix
func mulAddMUpperTriangularWithTransposeMatXMat(acc []uint64, m1 []uint64, m2 []uint8, rows int, cols2 int) {
	m1pos := 0
	for r := 0; r < rows; r++ {
		for c := r; c < rows; c++ {
			if c == r {
				m1pos += 1
				continue
			}
			for k := 0; k < cols2; k++ {
				vecMulAddPacked(P, m1[P*m1pos:], m2[c*cols2+k], acc[P*(r*cols2+k):])
				vecMulAddPacked(P, m1[P*m1pos:], m2[r*cols2+k], acc[P*(c*cols2+k):])
			}
			m1pos++
		}
	}
}

func mulAddMatVec(acc []byte, m []byte, v []byte, rows, cols int) {
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			acc[i] ^= byte(mulAddPacked(uint64(m[i*cols+j]), v[j]))
		}
	}
}

func upper(in []uint64, out []uint64, size int) {
	pos := 0
	for r := 0; r < size; r++ {
		for c := r; c < size; c++ {
			copy(out[P*pos:][:P], in[P*(r*size+c):][:P])
			if r != c {
				for p := 0; p < P; p++ {
					out[P*pos+p] ^= in[P*(c*size+r)+p]
				}
			}
			pos++
		}
	}
}

// The variable time technique is describe in the "Nibbling" paper (https://eprint.iacr.org/2023/1683.pdf)
// Section 4 (and Figure 2).
func calculatePStVarTime(sps []uint64, p1 []uint64, p2 []uint64, p3 []uint64, s []uint8) {
	var accumulator [K * N][P * 16]uint64

	// compute P * S^t = [ P1  P2 ] * [S1^t] = [P1*S1^t + P2*S2^t]
	//                   [  0  P3 ]   [S2^t]   [          P3*S2^t]

	// Note that S = S1||S2 is strided at N=V+O

	// P1 * S1^t : VxV * V*K, where P1 is triangular
	pos := 0
	for r := 0; r < V; r++ {
		for c := r; c < V; c++ {
			for k := 0; k < K; k++ {
				vecAddPacked(p1[P*pos:], accumulator[r*K+k][P*int(s[k*N+c]):])
			}
			pos++
		}
	}

	// P2 * S2^t : V*O * O*K
	pos = 0
	for r := 0; r < V; r++ {
		for c := 0; c < O; c++ {
			for k := 0; k < K; k++ {
				vecAddPacked(p2[P*pos:], accumulator[r*K+k][P*int(s[k*N+V+c]):])
			}
			pos++
		}
	}

	// P3 * S2^t : O*O * O*K, where P3 is triangular
	pos = 0
	for r := 0; r < O; r++ {
		for c := r; c < O; c++ {
			for k := 0; k < K; k++ {
				vecAddPacked(p3[P*pos:], accumulator[(r+V)*K+k][P*int(s[k*N+V+c]):])
			}
			pos++
		}
	}

	for i := 0; i < K*N; i++ {
		accumulate(P, accumulator[i], sps[P*i:])
	}
}

func calculateSPstVarTime(sps []uint64, s []uint8, pst []uint64) {
	var accumulator [K * K][P * 16]uint64

	// S * PST : KxN * N*K
	for r := 0; r < K; r++ {
		for c := 0; c < N; c++ {
			for k := 0; k < K; k++ {
				vecAddPacked(pst[P*(c*K+k):], accumulator[r*K+k][P*int(s[r*N+c]):])
			}
		}
	}

	for i := 0; i < K*K; i++ {
		accumulate(P, accumulator[i], sps[P*i:])
	}
}

func vecAddPacked(in []uint64, acc []uint64) {
	for i := 0; i < P; i++ {
		acc[i] ^= in[i]
	}
}

func accumulate(p int, bins [P * 16]uint64, out []uint64) {
	// The following two approches are mathematically equivalent, but the second one is slightly faster.

	// Here we chose to multiply by x^-1 all the way through,
	// unlike Method 3 in Figure 2 (see paper) which interleaves *x and *x^-1
	// which probably gives more parallelism on more complex CPUs.
	//
	// Also, on M1 Pro, Method 2 in Figure 2 is not faster then Approach 2 coded here.

	// Approach 1. Multiplying by x all the way through:
	// the powers of x mod x^4+x+1, represented as integers, are 1,2,4,8,3,..,13,9
	// vecMulAddPackedByX(p, bins[P*9:], bins[P*13:])
	// vecMulAddPackedByX(p, bins[P*13:], bins[P*15:])
	// vecMulAddPackedByX(p, bins[P*15:], bins[P*14:])
	// vecMulAddPackedByX(p, bins[P*14:], bins[P*7:])
	// vecMulAddPackedByX(p, bins[P*7:], bins[P*10:])
	// vecMulAddPackedByX(p, bins[P*10:], bins[P*5:])
	// vecMulAddPackedByX(p, bins[P*5:], bins[P*11:])
	// vecMulAddPackedByX(p, bins[P*11:], bins[P*12:])
	// vecMulAddPackedByX(p, bins[P*12:], bins[P*6:])
	// vecMulAddPackedByX(p, bins[P*6:], bins[P*3:])
	// vecMulAddPackedByX(p, bins[P*3:], bins[P*8:])
	// vecMulAddPackedByX(p, bins[P*8:], bins[P*4:])
	// vecMulAddPackedByX(p, bins[P*4:], bins[P*2:])
	// vecMulAddPackedByX(p, bins[P*2:], bins[P*1:])
	// copy(out[:P], bins[P*1:])

	// Approach 2. Multiplying by x^-1 all the way through:
	// In the reversed order of the first approach, because /x turns out to be slightly faster than *x.
	vecMulAddPackedByInvX(p, bins[P*2:], bins[P*4:])
	vecMulAddPackedByInvX(p, bins[P*4:], bins[P*8:])
	vecMulAddPackedByInvX(p, bins[P*8:], bins[P*3:])
	vecMulAddPackedByInvX(p, bins[P*3:], bins[P*6:])
	vecMulAddPackedByInvX(p, bins[P*6:], bins[P*12:])
	vecMulAddPackedByInvX(p, bins[P*12:], bins[P*11:])
	vecMulAddPackedByInvX(p, bins[P*11:], bins[P*5:])
	vecMulAddPackedByInvX(p, bins[P*5:], bins[P*10:])
	vecMulAddPackedByInvX(p, bins[P*10:], bins[P*7:])
	vecMulAddPackedByInvX(p, bins[P*7:], bins[P*14:])
	vecMulAddPackedByInvX(p, bins[P*14:], bins[P*15:])
	vecMulAddPackedByInvX(p, bins[P*15:], bins[P*13:])
	vecMulAddPackedByInvX(p, bins[P*13:], bins[P*9:])
	vecMulAddPackedByInvX(p, bins[P*9:], bins[P*1:])
	copy(out[:P], bins[P*1:])
}

// func vecMulAddPackedByX(p int, in []uint64, acc []uint64) {
// 	// vecMulAddPacked(p, in, 2, acc)

// 	msb := uint64(0x8888888888888888)
// 	for i := 0; i < p; i++ {
// 		t := in[i] & msb
// 		acc[i] ^= ((in[i] ^ t) << 1) ^ ((t >> 3) * 3)
// 	}
// }

// It can be seen by comparison to the commented code above that this requires fewer instructions.
func vecMulAddPackedByInvX(p int, in []uint64, acc []uint64) {
	// Equivalently:
	// vecMulAddPacked(p, in, 9, acc)

	lsb := uint64(0x1111111111111111)
	for i := 0; i < p; i++ {
		t := in[i] & lsb
		acc[i] ^= ((in[i] ^ t) >> 1) ^ (t * 9)
	}
}
