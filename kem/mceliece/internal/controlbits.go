// This file is for implementing the Nassimi-Sahni algorithm
// See David Nassimi, Sartaj Sahni "Parallel algorithms to set up the Benes permutationnetwork"
// See also https://cr.yp.to/papers/controlbits-20200923.pdf

package internal

import (
	"unsafe"
)

// layer implements one layer of the Beneš network.
// It permutes elements `p` according to control bits `cb` in-place.
// Thus, one layer of the Beneš network is created and if some control bits are set
// the corresponding transposition is applied. Parameter `s` equals `n.len()` and
// `s` configures `stride-2^s` conditional swaps.
func layer(p []int16, cb []byte, s, n int) {
	stride := 1 << s
	index := 0
	for i := int(0); i < n; i += stride * 2 {
		for j := int(0); j < stride; j++ {
			d := p[i+j] ^ p[i+j+stride]
			m := int16(cb[index>>3]>>(index&7)) & 1
			m = -m
			d &= m
			p[i+j] ^= d
			p[i+j+stride] ^= d
			index++
		}
	}
}

// cbRecursion implements a recursion step of controlbitsfrompermutation.
// Pick `w ∈ {1, 2, …, 14}. Let `n = 2^w`.
// `out` must be a reference to a slice with `((2*w-1)*(1<<(w-1))+7)/8` or more bytes.
// It must zero-initialized before the first recursive call.
// `step` is initialized with 0 and doubles in each recursion step.
// `pi_offset` is an offset within temp slice ref (or aux in the first recursive call).
// `temp` is an intermediate reference to a slice used for recursive computation and
// temporarily stores values. It must be able to carry at least 2・n elements.
// `aux` is an auxiliary reference to a slice. It points to the elements to be permuted.
// After the first recursive iterations, the elements are stored in `temp` and thus `aux`
// won't be read anymore. The first `n/2` elements are read.
// nolint:funlen
func cbRecursion(out []byte, pos, step int, pi []int16, w, n int32, temp []int32) {
	A := temp
	B := temp[n:]
	if w == 1 {
		out[pos>>3] ^= byte(pi[0] << (pos & 7))
		return
	}

	for x := int32(0); x < n; x++ {
		A[x] = (int32(pi[x]^1) << 16) | int32(pi[x^1])
	}
	int32Sort(A, n) // A = (id<<16)+pibar

	for x := int32(0); x < n; x++ {
		Ax := A[x]
		px := Ax & 0xffff
		cx := px
		if x < cx {
			cx = x
		}
		B[x] = (px << 16) | cx
	}
	// B = (p<<16)+c

	for x := int32(0); x < n; x++ {
		A[x] = (A[x] << 16) | x
	}
	int32Sort(A, n) // A = (id<<16)+pibar^-1

	for x := int32(0); x < n; x++ {
		// A = (pibar^(-1)<<16)+pibar
		A[x] = (A[x] << 16) + (B[x] >> 16)
	}
	int32Sort(A, n) // A = (id<<16)+pibar^2

	if w <= 10 {
		for x := int32(0); x < n; x++ {
			B[x] = ((A[x] & 0xffff) << 10) | (B[x] & 0x3ff)
		}

		for i := int32(1); i < w-1; i++ {
			/* B = (p<<10)+c */

			for x := int32(0); x < n; x++ {
				A[x] = ((B[x] & ^0x3ff) << 6) | x /* A = (p<<16)+id */
			}
			int32Sort(A, n) /* A = (id<<16)+p^{-1} */

			for x := int32(0); x < n; x++ {
				A[x] = (A[x] << 20) | B[x] /* A = (p^{-1}<<20)+(p<<10)+c */
			}
			int32Sort(A, n) /* A = (id<<20)+(pp<<10)+cp */

			for x := int32(0); x < n; x++ {
				ppcpx := A[x] & 0xfffff
				ppcx := (A[x] & 0xffc00) | (B[x] & 0x3ff)
				if ppcpx < ppcx {
					ppcx = ppcpx
				}
				B[x] = ppcx
			}
		}

		for x := int32(0); x < n; x++ {
			B[x] &= 0x3ff
		}
	} else {
		for x := int32(0); x < n; x++ {
			B[x] = (A[x] << 16) | (B[x] & 0xffff)
		}

		for i := int32(1); i < w-1; i++ {
			/* B = (p<<16)+c */

			for x := int32(0); x < n; x++ {
				A[x] = (B[x] &^ 0xffff) | x
			}
			int32Sort(A, n) /* A = (id<<16)+p^(-1) */

			for x := int32(0); x < n; x++ {
				A[x] = (A[x] << 16) | (B[x] & 0xffff)
			}
			/* A = p^(-1)<<16+c */

			if i < w-2 {
				for x := int32(0); x < n; x++ {
					B[x] = (A[x] & ^0xffff) | (B[x] >> 16)
				}
				/* B = (p^(-1)<<16)+p */
				int32Sort(B, n) /* B = (id<<16)+p^(-2) */
				for x := int32(0); x < n; x++ {
					B[x] = (B[x] << 16) | (A[x] & 0xffff)
				}
				/* B = (p^(-2)<<16)+c */
			}

			int32Sort(A, n)
			/* A = id<<16+cp */
			for x := int32(0); x < n; x++ {
				cpx := (B[x] & ^0xffff) | (A[x] & 0xffff)
				if cpx < B[x] {
					B[x] = cpx
				}
			}
		}

		for x := int32(0); x < n; x++ {
			B[x] &= 0xffff
		}
	}

	for x := int32(0); x < n; x++ {
		A[x] = (int32(pi[x]) << 16) + x
	}
	int32Sort(A, n) /* A = (id<<16)+pi^(-1) */

	for j := int32(0); j < n/2; j++ {
		x := 2 * j
		fj := B[x] & 1 /* f[j] */
		Fx := x + fj   /* F[x] */
		Fx1 := Fx ^ 1  /* F[x+1] */

		out[pos>>3] ^= byte(fj << (pos & 7))
		pos += step

		B[x] = (A[x] << 16) | Fx
		B[x+1] = (A[x+1] << 16) | Fx1
	}
	/* B = (pi^(-1)<<16)+F */

	int32Sort(B, n) /* B = (id<<16)+F(pi) */

	pos += int(2*w-3) * step * int(n/2)

	for k := int32(0); k < n/2; k++ {
		y := 2 * k
		lk := B[y] & 1 /* l[k] */
		Ly := y + lk   /* L[y] */
		Ly1 := Ly ^ 1  /* L[y+1] */

		out[pos>>3] ^= byte(lk << (pos & 7))
		pos += step

		A[y] = (Ly << 16) | (B[y] & 0xffff)
		A[y+1] = (Ly1 << 16) | (B[y+1] & 0xffff)
	}
	/* A = (L<<16)+F(pi) */

	int32Sort(A, n) /* A = (id<<16)+F(pi(L)) = (id<<16)+M */

	pos -= int(2*w-2) * step * int(n/2)

	p := (*int16)(unsafe.Pointer(&temp[n+n/4]))
	q := unsafe.Slice(p, n) // q can start anywhere between temp+n and temp+n/2
	for j := int32(0); j < n/2; j++ {
		q[j] = int16(A[2*j]&0xffff) >> 1
		q[j+n/2] = int16(A[2*j+1]&0xffff) >> 1
	}

	cbRecursion(out, pos, step*2, q, w-1, n/2, temp)
	cbRecursion(out, pos+step, step*2, q[n/2:], w-1, n/2, temp)
}

// ControlBitsFromPermutation computes control bits
// parameters: 1 <= w <= 14; n = 2^w
// input: permutation pi of {0,1,...,n-1}
// output: (2m-1)n/2 control bits at positions 0,1,...
// output position pos is by definition 1&(out[pos/8]>>(pos&7))
func ControlBitsFromPermutation(out []byte, pi []int16, w, n int32) {
	temp := make([]int32, 2*n)
	piTest := make([]int16, n)
	var ptr []byte
	for {
		for i := 0; i < int(((2*w-1)*n/2)+7)/8; i++ {
			out[i] = 0
		}

		cbRecursion(out, 0, 1, pi[:], w, n, temp)
		// check for correctness

		for i := int32(0); i < n; i++ {
			piTest[i] = int16(i)
		}

		ptr = out
		for i := 0; i < int(w); i++ {
			layer(piTest, ptr, i, int(n))
			ptr = ptr[n>>4:]
		}

		for i := int(w - 2); i >= 0; i-- {
			layer(piTest, ptr, i, int(n))
			ptr = ptr[n>>4:]
		}

		diff := int16(0)
		for i := int32(0); i < n; i++ {
			diff |= pi[i] ^ piTest[i]
		}

		if diff == 0 {
			break
		}
	}
}
