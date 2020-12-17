//go:generate go run src.go -out ../amd64.s -stubs ../stubs_amd64.go -pkg common
// +build ignore

// AVX2 optimized version of polynomial operations.  See the comments on the
// generic implementation for the details of the maths involved.
package main

import (
	. "github.com/mmcloughlin/avo/build"   // nolint:golint,stylecheck
	. "github.com/mmcloughlin/avo/operand" // nolint:golint,stylecheck
	. "github.com/mmcloughlin/avo/reg"     // nolint:golint,stylecheck

	"github.com/cloudflare/circl/pke/kyber/internal/common/params"
)

// XXX align Poly on 16 bytes such that we can use aligned moves
// XXX ensure Zetas and ZetasAVX2 are 16 byte aligned

// Barrett reduces the int16x16 where q must contain {q, q, …};
// num must contain {20159, 20159, …} the numerator in the approximation
// 20159/2²⁶ of 1/q and t is a temporary register that will be clobbered.
func barrettReduceX16(x, q, num, t Op) {
	// Recall that the Barrett reduction of x is given by
	//
	//  x - int16((int32(x)*20159)>>26)*q

	VPMULHW(num, x, t)   // t := (int32(x) * 20159) >> 16
	VPSRAW(U8(10), t, t) // t = int16(t)>>10 so that t = (int32(x)*20159) >> 26
	VPMULLW(q, t, t)     // t *= q
	VPSUBW(t, x, x)      // x -= t
}

func broadcastImm16(c int16, out Op) {
	tmp1 := GP32()
	tmp2 := XMM()
	MOVL(U32(uint32(int32(c))), tmp1)
	VMOVD(tmp1, tmp2)
	VPBROADCASTW(tmp2, out)
}

func addAVX2() {
	TEXT("addAVX2", NOSPLIT, "func(p, a, b *[256]int16)")
	Pragma("noescape")

	pPtr := Load(Param("p"), GP64())
	aPtr := Load(Param("a"), GP64())
	bPtr := Load(Param("b"), GP64())

	var a [8]VecVirtual
	var b [8]VecVirtual
	for i := 0; i < 8; i++ {
		a[i] = YMM()
		b[i] = YMM()
	}

	for j := 0; j < 2; j++ {
		for i := 0; i < 8; i++ {
			VMOVDQU(Mem{Base: aPtr, Disp: 32 * (8*j + i)}, a[i])
		}
		for i := 0; i < 8; i++ {
			VMOVDQU(Mem{Base: bPtr, Disp: 32 * (8*j + i)}, b[i])
		}
		for i := 0; i < 8; i++ {
			VPADDW(a[i], b[i], b[i])
		}
		for i := 0; i < 8; i++ {
			VMOVDQU(b[i], Mem{Base: pPtr, Disp: 32 * (8*j + i)})
		}
	}

	RET()
}

func subAVX2() {
	TEXT("subAVX2", NOSPLIT, "func(p, a, b *[256]int16)")
	Pragma("noescape")

	pPtr := Load(Param("p"), GP64())
	aPtr := Load(Param("a"), GP64())
	bPtr := Load(Param("b"), GP64())

	var a [8]VecVirtual
	var b [8]VecVirtual
	for i := 0; i < 8; i++ {
		a[i] = YMM()
		b[i] = YMM()
	}

	for j := 0; j < 2; j++ {
		for i := 0; i < 8; i++ {
			VMOVDQU(Mem{Base: aPtr, Disp: 32 * (8*j + i)}, a[i])
		}
		for i := 0; i < 8; i++ {
			VMOVDQU(Mem{Base: bPtr, Disp: 32 * (8*j + i)}, b[i])
		}
		for i := 0; i < 8; i++ {
			VPSUBW(b[i], a[i], b[i])
		}
		for i := 0; i < 8; i++ {
			VMOVDQU(b[i], Mem{Base: pPtr, Disp: 32 * (8*j + i)})
		}
	}

	RET()
}

// For each lane in a that has a 1 on ith bit of its index, swap it with
// the corresponding lane in b where this 1 has been replaced by a 0.
//
// For instance, if i=2, then this will swap
//
//   a[0b0100] ↔ b[0b0000]    a[0b0101] ↔ b[0b0001]
//   a[0b0110] ↔ b[0b0010]    a[0b0111] ↔ b[0b0011]
//   a[0b1100] ↔ b[0b1000]    a[0b1101] ↔ b[0b1001]
//   a[0b1110] ↔ b[0b1010]    a[0b1111] ↔ b[0b1011]
//
// and keep all other lanes in their place.  If we index the lanes of a and
// b consecutively (i.e. 0wxyz is wxyz of a and 1wxyz = wxyz of b), then
// this corresponds to mapping lane vwxyz to xwvyz -- that is: flipping the
// fourth bit with the ith bit (where we start from zeroth.)  Hence the name.
//
// Why these permutations?  There are two reasons: these are reasonable
// easy to implement and they pull sequential butterflies in the NTT apart.
// Recall, namely, that on the fifth layer of the NTT we're computing
// butteflies between indices
//
//      abcd0fgh  abcd1fgh
//
// Applying bitflip with i=3 beforehand, the butterflies become
//
//      abc0dfgh  abc1dfgh
//
// which allows for 16 consecutive butterflies, which is convenient for AVX2.
// What we'll actually end up doing is a bit different: we'll apply both
// an i=3 and i=2 bitflip before then to also interleave the ζs correctly
// for the fourth layer.
//
// See the diagram linked to in the documentation of nttAVX2().
func bitflip(i int, a, b, t Op) {
	switch i {
	case 3:
		VPERM2I128(U8(0x20), b, a, t)
		VPERM2I128(U8(0x31), b, a, b)
		VMOVDQA(t, a)
	case 2:
		VPUNPCKLQDQ(b, a, t)
		VPUNPCKHQDQ(b, a, b)
		VMOVDQA(t, a)
	case 1:
		VMOVSLDUP(b, t)
		VPBLENDD(U8(0xaa), t, a, t)
		VPSRLQ(U8(32), a, a)
		VPBLENDD(U8(0xaa), b, a, b)
		VMOVDQA(t, a)
	case 0:
		VPSLLD(U8(16), b, t)
		VPBLENDW(U8(0xaa), t, a, t)
		VPSRLD(U8(16), a, a)
		VPBLENDW(U8(0xaa), b, a, b)
		VMOVDQA(t, a)
	}
}

func invNttAVX2() {
	// This AVX2-optimized inverse NTT is close, but more disimilar from
	// the generic inverse NTT, then the AVX2-optimized forward NTT is
	// from the generic.
	//
	//  1. Just like in the AVX2-optimized forward NTT, we shuffle the
	//     coefficients around to ensure we can do consecutive butterflies and
	//  2. we use the same preshuffled and duplicated ZetasAVX2 table.
	//  3. Barrett reductions are computed at different moments as it's very
	//     efficient to do 16 at a time.

	// The butterflies and swaps are in the exact reverse order as those
	// of the AVX2-optimized forward NTT.  See the comments on nttAVX2()
	// and bitflip() for documentation on the shufflings.

	// A diagram of the order of the butterflies and swaps can be found here:
	//
	//  https://github.com/cloudflare/circl/wiki/images/kyber-invntt-avx2.svg
	//
	// The vertical lines with circles on the end represent butterflies.
	// The number in those butterflies refers to the index into the Zetas
	// array of which ζ is used.  (Note that this array is different from
	// the ZetasAVX2 array, which contains the elements of Zetas many times
	// over in a way that is efficient for our implementation.)
	//
	// The green squares represent Barrett reductions.  The green numbers after
	// the butterflies show the multiple of q that bounds the coefficient in
	// absolute value.  (Recall that the lower coefficient is always bounded
	// by one when computing the inverse butterflies in the obvious way.)
	// The vertical lines with crosses on them represent a swap.

	TEXT("invNttAVX2", NOSPLIT, "func(p *[256]int16)")
	Pragma("noescape")
	pPtr := Load(Param("p"), GP64())
	zetasPtr := GP64()
	LEAQ(NewDataAddr(Symbol{Name: "·ZetasAVX2"}, 0), zetasPtr)

	// Compute 4x16 Gentleman--Sande butterflies (a, b) ↦ (a + b, ζ(a - b)).
	//
	// There is a catch: the first two and the last two sets of butterflies
	// have to use the same sets of zetas, as we don't have enough registers
	// to keep everything around.  t1 up to t4 are temporary registers that
	// will be clobbered.
	gsButterfly := func(a1, b1, a2, b2, zeta12l, zeta12h,
		a3, b3, a4, b4, zeta34l, zeta34h, t1, t2, t3, t4, q Op) {

		// In the generic implementation, a single butterfly is computed as
		// follows (unfolding the definition of montReduce and recalling
		// zeta stores -ζ.)
		//
		//  t := b - a
		//  a += b
		//  m := int16(zeta * t * 62209)
		//  b = int16(uint32(zeta * int32(t) - m * int32(Q)) >> 16)
		//
		// As ζt ≡ mq (mod 2¹⁶), see comments on montReduce(), we can
		// also compute b as
		//
		//  b = (uint32(zeta * int32(t)) >> 16) - (uint32(m * int32(Q)) >> 16)
		//
		// m (x16) can be computed using a single VPMULLW with zeta * 62209
		// as the second operand stored in a table.  The two multiplications
		// and bitshifts for b can be performed using two VPMULHWs (again
		// for 16 at a time.)

		VPSUBW(a1, b1, t1) // t = b - a
		VPSUBW(a2, b2, t2)
		VPSUBW(a3, b3, t3)

		// We don't use t4 yet, so that zeta12l may be used as t4.

		VPADDW(a1, b1, a1) // a += b
		VPADDW(a2, b2, a2)
		VPADDW(a3, b3, a3)

		VPMULLW(t1, zeta12l, b1) // m = int16(zeta * t * 62209)
		VPMULLW(t2, zeta12l, b2)

		// At this point zeta12l (which might equal t4) is free.
		VPSUBW(a4, b4, t4)

		VPMULLW(t3, zeta34l, b3)

		VPADDW(a4, b4, a4)

		VPMULLW(t4, zeta34l, b4)

		VPMULHW(t1, zeta12h, t1) // uint32(zeta*int32(t)) >> 16
		VPMULHW(t2, zeta12h, t2)
		VPMULHW(t3, zeta34h, t3)
		VPMULHW(t4, zeta34h, t4)

		VPMULHW(b1, q, b1) // uint32(m*int32(Q)) >> 16
		VPMULHW(b2, q, b2)
		VPMULHW(b3, q, b3)
		VPMULHW(b4, q, b4)

		VPSUBW(b1, t1, b1) // Compute b
		VPSUBW(b2, t2, b2)
		VPSUBW(b3, t3, b3)
		VPSUBW(b4, t4, b4)
	}

	// Registers and constants
	var xs [8]VecVirtual
	zs := [4]VecVirtual{YMM(), YMM(), YMM(), YMM()}
	ts := [3]VecVirtual{YMM(), YMM(), YMM()}
	for i := 0; i < 8; i++ {
		xs[i] = YMM()
	}

	q := YMM()
	broadcastImm16(params.Q, q)

	// Layers 1 - 6
	for offset := 0; offset < 2; offset++ {
		for i := 0; i < 8; i++ {
			VMOVDQU(Mem{Base: pPtr, Disp: 32 * (i + offset*8)}, xs[i])
		}

		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (33 + offset*4)}, zs[0])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (33 + offset*4 + 1)}, zs[1])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (33 + offset*4 + 2)}, zs[2])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (33 + offset*4 + 3)}, zs[3])

		// Layer 1 (inverse of 7)

		gsButterfly(
			xs[0], xs[2], // a1, b1
			xs[1], xs[3], // a2, b2
			zs[0], zs[1], // zs12l, zs12h
			xs[4], xs[6], // a3, b3,
			xs[5], xs[7], // a4, b4,
			zs[2], zs[3], // zs34l, zs34h
			ts[0], ts[1], ts[2], zs[0], // t1, t2, t3, t4
			q, // q
		)

		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (41 + offset*4)}, zs[0])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (41 + offset*4 + 1)}, zs[1])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (41 + offset*4 + 2)}, zs[2])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (41 + offset*4 + 3)}, zs[3])

		bitflip(0, xs[0], xs[1], ts[0])
		bitflip(0, xs[2], xs[3], ts[0])
		bitflip(0, xs[4], xs[5], ts[0])
		bitflip(0, xs[6], xs[7], ts[0])

		// Layer 2 (inverse of 6)

		gsButterfly(
			xs[0], xs[1], // a1, b1
			xs[2], xs[3], // a2, b2
			zs[0], zs[1], // zs12l, zs12h
			xs[4], xs[5], // a3, b3,
			xs[6], xs[7], // a4, b4,
			zs[2], zs[3], // zs34l, zs34h
			ts[0], ts[1], ts[2], zs[0], // t1, t2, t3, t4
			q, // q
		)

		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (49 + offset*4)}, zs[0])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (49 + offset*4 + 1)}, zs[1])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (49 + offset*4 + 2)}, zs[2])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (49 + offset*4 + 3)}, zs[3])

		bitflip(1, xs[0], xs[2], ts[0])
		bitflip(1, xs[1], xs[3], ts[0])
		bitflip(1, xs[4], xs[6], ts[0])
		bitflip(1, xs[5], xs[7], ts[0])

		// Layer 3 (inverse of 5)

		gsButterfly(
			xs[0], xs[2], // a1, b1
			xs[1], xs[3], // a2, b2
			zs[0], zs[1], // zs12l, zs12h
			xs[4], xs[6], // a3, b3,
			xs[5], xs[7], // a4, b4,
			zs[2], zs[3], // zs34l, zs34h
			ts[0], ts[1], ts[2], zs[0], // t1, t2, t3, t4
			q, // q
		)

		broadcastImm16(20159, ts[0])
		barrettReduceX16(xs[0], q, ts[0], ts[1])
		barrettReduceX16(xs[4], q, ts[0], ts[1])

		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (57 + offset*4)}, zs[0])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (57 + offset*4 + 1)}, zs[1])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (57 + offset*4 + 2)}, zs[2])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (57 + offset*4 + 3)}, zs[3])

		bitflip(2, xs[0], xs[1], ts[0])
		bitflip(2, xs[2], xs[3], ts[0])
		bitflip(2, xs[4], xs[5], ts[0])
		bitflip(2, xs[6], xs[7], ts[0])

		// Layer 4 (inverse of 4)

		gsButterfly(
			xs[0], xs[1], // a1, b1
			xs[2], xs[3], // a2, b2
			zs[0], zs[1], // zs12l, zs12h
			xs[4], xs[5], // a3, b3,
			xs[6], xs[7], // a4, b4,
			zs[2], zs[3], // zs34l, zs34h
			ts[0], ts[1], ts[2], zs[0], // t1, t2, t3, t4
			q, // q
		)

		VPBROADCASTW(Mem{Base: zetasPtr, Disp: 32*65 + 2*(4*offset)}, zs[0])
		VPBROADCASTW(Mem{Base: zetasPtr, Disp: 32*65 + 2*(4*offset+1)}, zs[1])
		VPBROADCASTW(Mem{Base: zetasPtr, Disp: 32*65 + 2*(4*offset+2)}, zs[2])
		VPBROADCASTW(Mem{Base: zetasPtr, Disp: 32*65 + 2*(4*offset+3)}, zs[3])

		bitflip(3, xs[0], xs[2], ts[0])
		bitflip(3, xs[1], xs[3], ts[0])
		bitflip(3, xs[4], xs[6], ts[0])
		bitflip(3, xs[5], xs[7], ts[0])

		// Layer 5 (inverse of 3)

		gsButterfly(
			xs[0], xs[2], // a1, b1
			xs[1], xs[3], // a2, b2
			zs[0], zs[1], // zs12l, zs12h
			xs[4], xs[6], // a3, b3,
			xs[5], xs[7], // a4, b4,
			zs[2], zs[3], // zs34l, zs34h
			ts[0], ts[1], ts[2], zs[0], // t1, t2, t3, t4
			q, // q
		)

		broadcastImm16(20159, ts[0])
		barrettReduceX16(xs[0], q, ts[0], ts[1])
		barrettReduceX16(xs[4], q, ts[0], ts[1])

		// Layer 6 (inverse of 2)

		VPBROADCASTW(Mem{Base: zetasPtr, Disp: 32*65 + 2*(8+2*offset)}, zs[0])
		VPBROADCASTW(Mem{Base: zetasPtr, Disp: 32*65 + 2*(8+2*offset+1)}, zs[1])

		gsButterfly(
			xs[0], xs[4], // a1, b1
			xs[1], xs[5], // a2, b2
			zs[0], zs[1], // zs12l, zs12h
			xs[2], xs[6], // a3, b3,
			xs[3], xs[7], // a4, b4,
			zs[0], zs[1], // zs34l, zs34h
			ts[0], ts[1], ts[2], zs[2], // t1, t2, t3, t4
			q, // q
		)

		for i := 0; i < 8; i++ {
			VMOVDQU(xs[i], Mem{Base: pPtr, Disp: 32 * (i + offset*8)})
		}
	}

	// Layers 7 (inverse of 1)

	for offset := 0; offset < 2; offset++ {
		VPBROADCASTW(Mem{Base: zetasPtr, Disp: 32*65 + 2*(12)}, zs[0])
		VPBROADCASTW(Mem{Base: zetasPtr, Disp: 32*65 + 2*(12+1)}, zs[1])

		for i := 0; i < 4; i++ {
			VMOVDQU(Mem{Base: pPtr, Disp: 32 * (i + offset*4)}, xs[i])
		}
		for i := 0; i < 4; i++ {
			VMOVDQU(Mem{Base: pPtr, Disp: 32 * (i + 8 + offset*4)}, xs[4+i])
		}

		gsButterfly(
			xs[0], xs[4], // a1, b1
			xs[1], xs[5], // a2, b2
			zs[0], zs[1], // zs12l, zs12h
			xs[2], xs[6], // a3, b3,
			xs[3], xs[7], // a4, b4,
			zs[0], zs[1], // zs34l, zs34h
			zs[2], zs[3], ts[0], ts[1], // t1, t2, t3, t4
			q, // q
		)

		// Finally, we set x = montgomeryReduce(x * 1441). Just like in the
		// the butterflies we compute the Montgomery reduction using
		// VPMULHWs and VPMULLWs by observing:
		//
		//  m := int16(1441 * x * 62209) = int16(-10079 * x)
		//  x' = int16(uint32(1441 * int32(x) - m * int32(Q)) >> 16)
		//     = (uint32(1441 * int32(x)) >> 16) - (uint32(m * int32(Q)) >> 16)

		broadcastImm16(-10079, zs[0])
		broadcastImm16(1441, zs[1])

		for j := 0; j < 2; j++ {
			VPMULLW(xs[4*j+0], zs[0], zs[2]) // m = int16(-10079 * x)
			VPMULLW(xs[4*j+1], zs[0], zs[3])
			VPMULLW(xs[4*j+2], zs[0], ts[0])
			VPMULLW(xs[4*j+3], zs[0], ts[1])

			VPMULHW(xs[4*j+0], zs[1], xs[4*j+0]) // uint32(1441*int32(x)) >> 16
			VPMULHW(xs[4*j+1], zs[1], xs[4*j+1])
			VPMULHW(xs[4*j+2], zs[1], xs[4*j+2])
			VPMULHW(xs[4*j+3], zs[1], xs[4*j+3])

			VPMULHW(zs[2], q, zs[2]) // uint32(m*int32(Q)) >> 16
			VPMULHW(zs[3], q, zs[3])
			VPMULHW(ts[0], q, ts[0])
			VPMULHW(ts[1], q, ts[1])

			VPSUBW(zs[2], xs[4*j+0], xs[4*j+0]) // computes t
			VPSUBW(zs[3], xs[4*j+1], xs[4*j+1])
			VPSUBW(ts[0], xs[4*j+2], xs[4*j+2])
			VPSUBW(ts[1], xs[4*j+3], xs[4*j+3])
		}

		for i := 0; i < 4; i++ {
			VMOVDQU(xs[i], Mem{Base: pPtr, Disp: 32 * (i + offset*4)})
		}
		for i := 0; i < 4; i++ {
			VMOVDQU(xs[4+i], Mem{Base: pPtr, Disp: 32 * (i + 8 + offset*4)})
		}
	}

	RET()
}

func nttAVX2() {
	// We perform almost the same operations as the generic implementation of NTT,
	// but use AVX2 to perform 64 butterflies at the same time.  We can keep
	// 128 coefficients in registers at the same time.  We do the first level
	// separately writing back to memory.  Then we do levels 2 through 7 for
	// 128 coefficients in registers all at the same time.

	// As we can only perform butterflies of 8 consecutive coefficients,
	// we need to shuffle coefficients around.  Similarly parallel
	// multiplication in the NTT-domain (as implemented by MulHat) requires
	// sequential coefficients to be pulled apart.  Thus we will use a
	// different order of coefficients than the reference implementation.

	// A diagram of the order of butterflies and swaps can be found here:
	//
	//  https://github.com/cloudflare/circl/wiki/images/kyber-ntt-avx2.svg
	//
	// The vertical lines with circles on the end represent butterflies.
	// The number in those butterflies refers to the index into the Zetas
	// array of which ζ is used.  (Note that this array is different from
	// the ZetasAVX2 array, which contains the elements of Zetas many times
	// over in a way that is efficient for our implementation.)
	//
	// The vertical lines with crosses on them represent a swap.

	// Related reading: https://eprint.iacr.org/2018/039.pdf

	TEXT("nttAVX2", NOSPLIT, "func(p *[256]int16)")
	Pragma("noescape")
	pPtr := Load(Param("p"), GP64())
	zetasPtr := GP64()
	LEAQ(NewDataAddr(Symbol{Name: "·ZetasAVX2"}, 0), zetasPtr)

	// Compute 4x16 Cooley--Tukey butterflies (a, b) ↦ (a + ζb, a - ζb).
	//
	// There is a catch: the first two and the last two sets of butterflies
	// have to use the same sets of zetas, as we don't have enough registers
	// to keep everything around.  t1 up to t4 are temporary registers that
	// will be clobbered.
	ctButterfly := func(a1, b1, a2, b2, zeta12l, zeta12h,
		a3, b3, a4, b4, zeta34l, zeta34h, t1, t2, t3, t4, q Op) {

		// In the generic implementation, a single butterfly is computed as
		// follows (unfolding the definition of montReduce):
		//
		//  m := int16(zeta * b * 62209)
		//  t := int16(uint32(zeta * int32(b) - m * int32(Q)) >> 16)
		//  b = a - t
		//  a += t
		//
		// As ζb ≡ mq (mod 2¹⁶), see comments on montReduce(), we can
		// also compute t as
		//
		//  t := (uint32(zeta * int32(b)) >> 16) - (uint32(m * int32(Q)) >> 16)
		//
		// m (x16) can be computed using a single VPMULLW with zeta * 62209
		// as the second operand stored in a table.  The two multiplications
		// and bitshifts for t can be performed using two VPMULHWs (again
		// for 16 at a time.)

		VPMULLW(b1, zeta12l, t1) // m = int16(zeta * b * 62209)
		VPMULLW(b2, zeta12l, t2)
		VPMULLW(b3, zeta34l, t3)
		VPMULLW(b4, zeta34l, t4)

		VPMULHW(b1, zeta12h, b1) // uint32(zeta*int32(b)) >> 16
		VPMULHW(b2, zeta12h, b2)
		VPMULHW(b3, zeta34h, b3)
		VPMULHW(b4, zeta34h, b4)

		VPMULHW(t1, q, t1) // uint32(m*int32(Q)) >> 16
		VPMULHW(t2, q, t2)
		VPMULHW(t3, q, t3)
		VPMULHW(t4, q, t4)

		VPSUBW(t1, b1, t1) // computes t
		VPSUBW(t2, b2, t2)
		VPSUBW(t3, b3, t3)
		VPSUBW(t4, b4, t4)

		VPSUBW(t1, a1, b1) // b = a - t
		VPSUBW(t2, a2, b2)
		VPSUBW(t3, a3, b3)
		VPSUBW(t4, a4, b4)

		VPADDW(t1, a1, a1) // a = a + t
		VPADDW(t2, a2, a2)
		VPADDW(t3, a3, a3)
		VPADDW(t4, a4, a4)
	}

	// First level:
	var xs [8]VecVirtual
	zs := [4]VecVirtual{YMM(), YMM(), YMM(), YMM()}
	ts := [3]VecVirtual{YMM(), YMM(), YMM()}
	for i := 0; i < 8; i++ {
		xs[i] = YMM()
	}

	q := YMM()
	broadcastImm16(params.Q, q)

	VPBROADCASTW(Mem{Base: zetasPtr}, zs[0])
	VPBROADCASTW(Mem{Base: zetasPtr, Disp: 2}, zs[1])

	for offset := 0; offset < 2; offset++ {
		for i := 0; i < 4; i++ {
			VMOVDQU(Mem{Base: pPtr, Disp: 32 * (i + offset*4)}, xs[i])
		}
		for i := 0; i < 4; i++ {
			VMOVDQU(Mem{Base: pPtr, Disp: 32 * (i + 8 + offset*4)}, xs[4+i])
		}

		ctButterfly(
			xs[0], xs[4], // a1, b1
			xs[1], xs[5], // a2, b2
			zs[0], zs[1], // zs12l, zs12h
			xs[2], xs[6], // a3, b3,
			xs[3], xs[7], // a4, b4,
			zs[0], zs[1], // zs34l, zs34h
			zs[2], zs[3], ts[0], ts[1], // t1, t2, t3, t4
			q, // q
		)

		for i := 0; i < 4; i++ {
			VMOVDQU(xs[i], Mem{Base: pPtr, Disp: 32 * (i + offset*4)})
		}
		for i := 0; i < 4; i++ {
			VMOVDQU(xs[4+i], Mem{Base: pPtr, Disp: 32 * (i + 8 + offset*4)})
		}
	}

	// Layers 2 - 7
	//
	// Layers 2 and 3 are straight forward.  From layers 4 onwards, the
	// shuffling begins.
	for offset := 0; offset < 2; offset++ {
		VPBROADCASTW(Mem{Base: zetasPtr, Disp: 2 * (2 * (1 + offset))}, zs[0])
		VPBROADCASTW(Mem{Base: zetasPtr, Disp: 2 * (2*(1+offset) + 1)}, zs[1])

		for i := 0; i < 8; i++ {
			VMOVDQU(Mem{Base: pPtr, Disp: 32 * (i + offset*8)}, xs[i])
		}

		// Layer 2
		ctButterfly(
			xs[0], xs[4], // a1, b1
			xs[1], xs[5], // a2, b2
			zs[0], zs[1], // zs12l, zs12h
			xs[2], xs[6], // a3, b3,
			xs[3], xs[7], // a4, b4,
			zs[0], zs[1], // zs34l, zs34h
			zs[2], zs[3], ts[0], ts[1], // t1, t2, t3, t4
			q, // q
		)

		VPBROADCASTW(Mem{Base: zetasPtr, Disp: 2 * (6 + 4*offset)}, zs[0])
		VPBROADCASTW(Mem{Base: zetasPtr, Disp: 2 * ((6 + 4*offset) + 1)}, zs[1])
		VPBROADCASTW(Mem{Base: zetasPtr, Disp: 2 * ((6 + 4*offset) + 2)}, zs[2])
		VPBROADCASTW(Mem{Base: zetasPtr, Disp: 2 * ((6 + 4*offset) + 3)}, zs[3])

		// Layer 3
		ctButterfly(
			xs[0], xs[2], // a1, b1
			xs[1], xs[3], // a2, b2
			zs[0], zs[1], // zs12l, zs12h
			xs[4], xs[6], // a3, b3,
			xs[5], xs[7], // a4, b4,
			zs[2], zs[3], // zs34l, zs34h
			ts[0], ts[1], ts[2], zs[0], // t1, t2, t3, t4
			q, // q
		)

		// Layer 4
		//
		// On this layer, the butterflies are of length 16 and so would still
		// fit.  However, the first set of butterflies uses Zetas[8], whereas
		// the second set uses Zetas[9].  On the next layer the butterflies
		// are each of length 8 and wouldn't fit.  We solve both issues now
		// by swapping the second part of the first set with the first part
		// of the second set, etc.  This is a bitflip() with i=4.

		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (1 + offset*4)}, zs[0])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (1 + offset*4 + 1)}, zs[1])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (1 + offset*4 + 2)}, zs[2])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (1 + offset*4 + 3)}, zs[3])

		bitflip(3, xs[0], xs[2], ts[0])
		bitflip(3, xs[1], xs[3], ts[0])
		bitflip(3, xs[4], xs[6], ts[0])
		bitflip(3, xs[5], xs[7], ts[0])

		ctButterfly(
			xs[0], xs[1], // a1, b1
			xs[2], xs[3], // a2, b2
			zs[0], zs[1], // zs12l, zs12h
			xs[4], xs[5], // a3, b3,
			xs[6], xs[7], // a4, b4,
			zs[2], zs[3], // zs34l, zs34h
			ts[0], ts[1], ts[2], zs[0], // t1, t2, t3, t4
			q, // q
		)

		// Layer 5
		//
		// On this layer, the butterflies are of length 8 and wouldn't fit
		// directly.  However, because of the previous shuffling we have
		// sets of 16 consecutive butterflies.  However, just like in the
		// previous layer, the ζs required by the two sets are different:
		// the first sets uses 16 & 17 whereas the second uses 18 - 19.
		// We solve the issue by swapping two pairs of quarters.  At the same
		// time this swapping also ensures that the next layer has consecutive
		// butterflies.  This is bitflip() with i=3.  There is some freedom
		// which pairs to flip.  We try to keep the permutations as local
		// as possible: there is only mixing between xs[0], xs[1], xs[2]
		// and xs[3].  As an added benefit this ensures that the final
		// complete permuation is convenient for multiplication.

		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (9 + offset*4)}, zs[0])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (9 + offset*4 + 1)}, zs[1])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (9 + offset*4 + 2)}, zs[2])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (9 + offset*4 + 3)}, zs[3])

		bitflip(2, xs[0], xs[1], ts[0])
		bitflip(2, xs[2], xs[3], ts[0])
		bitflip(2, xs[4], xs[5], ts[0])
		bitflip(2, xs[6], xs[7], ts[0])

		ctButterfly(
			xs[0], xs[2], // a1, b1
			xs[1], xs[3], // a2, b2
			zs[0], zs[1], // zs12l, zs12h
			xs[4], xs[6], // a3, b3,
			xs[5], xs[7], // a4, b4,
			zs[2], zs[3], // zs34l, zs34h
			ts[0], ts[1], ts[2], zs[0], // t1, t2, t3, t4
			q, // q
		)

		// Layer 6
		//
		// We continue on with the same principle.

		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (17 + offset*4)}, zs[0])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (17 + offset*4 + 1)}, zs[1])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (17 + offset*4 + 2)}, zs[2])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (17 + offset*4 + 3)}, zs[3])

		bitflip(1, xs[0], xs[2], ts[0])
		bitflip(1, xs[1], xs[3], ts[0])
		bitflip(1, xs[4], xs[6], ts[0])
		bitflip(1, xs[5], xs[7], ts[0])

		ctButterfly(
			xs[0], xs[1], // a1, b1
			xs[2], xs[3], // a2, b2
			zs[0], zs[1], // zs12l, zs12h
			xs[4], xs[5], // a3, b3,
			xs[6], xs[7], // a4, b4,
			zs[2], zs[3], // zs34l, zs34h
			ts[0], ts[1], ts[2], zs[0], // t1, t2, t3, t4
			q, // q
		)

		// Layer 7

		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (25 + offset*4)}, zs[0])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (25 + offset*4 + 1)}, zs[1])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (25 + offset*4 + 2)}, zs[2])
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (25 + offset*4 + 3)}, zs[3])

		bitflip(0, xs[0], xs[1], ts[0])
		bitflip(0, xs[2], xs[3], ts[0])
		bitflip(0, xs[4], xs[5], ts[0])
		bitflip(0, xs[6], xs[7], ts[0])

		ctButterfly(
			xs[0], xs[2], // a1, b1
			xs[1], xs[3], // a2, b2
			zs[0], zs[1], // zs12l, zs12h
			xs[4], xs[6], // a3, b3,
			xs[5], xs[7], // a4, b4,
			zs[2], zs[3], // zs34l, zs34h
			ts[0], ts[1], ts[2], zs[0], // t1, t2, t3, t4
			q, // q
		)

		for i := 0; i < 8; i++ {
			VMOVDQU(xs[i], Mem{Base: pPtr, Disp: 32 * (i + offset*8)})
		}
	}

	RET()
}

func mulHatAVX2() {
	TEXT("mulHatAVX2", NOSPLIT, "func(p, a, b *[256]int16)")
	Pragma("noescape")

	pPtr := Load(Param("p"), GP64())
	aPtr := Load(Param("a"), GP64())
	bPtr := Load(Param("b"), GP64())

	zetasPtr := GP64()
	LEAQ(NewDataAddr(Symbol{Name: "·ZetasAVX2"}, 0), zetasPtr)

	a := []Op{YMM(), YMM(), YMM(), YMM()}
	b := []Op{YMM(), YMM(), YMM(), YMM()}
	t := []Op{YMM(), YMM(), YMM(), YMM()}

	zl := YMM()
	zh := YMM()
	qinv := YMM()
	q := YMM()

	broadcastImm16(-3327, qinv) // = q⁻¹ (mod 2¹⁶)
	broadcastImm16(params.Q, q)

	for j := 0; j < 4; j++ {
		for i := 0; i < 4; i++ {
			VMOVDQU(Mem{Base: aPtr, Disp: 32 * (4*j + i)}, a[i])
		}
		for i := 0; i < 4; i++ {
			VMOVDQU(Mem{Base: bPtr, Disp: 32 * (4*j + i)}, b[i])
		}

		// Recall that quite conveniently for this computation (when j=0),
		//
		//  a[0] contains a₀, a₄, ..., a₆₀,
		//  a[1] contains a₁, a₅, ..., a₆₁,
		//  a[2] contains a₂, a₆, ..., a₆₂ and
		//  a[3] contains a₃, a₇, ..., a₆₃
		//
		// and a similar thing for b, p and j>0.

		// We have to compute several products of the form t=montReduce(a*b).
		// From the discussion in AVX2-optimized NTT, recall that we can
		// compute this as follows.
		//
		//  m := int16(a * b * 62209) = int16(a * b * -3227)
		//  t := int16(uint32(int32(a) * int32(b) - m * int32(Q)) >> 16)
		//     = (uint32(int32(a) * int32(b))>>16) - (uint32(m * int32(Q))>>16)

		// We start with the first four lines of
		//
		//  p0 := montReduce(int32(a[i+1]) * int32(b[i+1]))
		//  p2 := montReduce(int32(a[i]) * int32(b[i]))
		//  p1 := montReduce(int32(a[i]) * int32(b[i+1]))
		//  p1 += montReduce(int32(a[i+1]) * int32(b[i]))
		//  p0 = montReduce(int32(p0) * zeta) + p2
		VPMULLW(a[1], b[1], t[0])
		VPMULLW(a[0], b[0], t[1])
		VPMULLW(a[0], b[1], t[2])
		VPMULLW(a[1], b[0], t[3])

		VPMULLW(t[0], qinv, t[0])
		VPMULLW(t[1], qinv, t[1])
		VPMULLW(t[2], qinv, t[2])
		VPMULLW(t[3], qinv, t[3])

		// zl and zh are used as temporary registers here
		VPMULHW(a[1], b[1], zl) // will end up in b[0]
		VPMULHW(a[0], b[0], zh) // will end up in b[1]
		VPMULHW(a[0], b[1], a[0])
		VPMULHW(a[1], b[0], a[1])
		VMOVDQA(zl, b[0])
		VMOVDQA(zh, b[1])

		VPMULHW(t[0], q, t[0])
		VPMULHW(t[1], q, t[1])
		VPMULHW(t[2], q, t[2])
		VPMULHW(t[3], q, t[3])

		VPSUBW(t[0], b[0], b[0]) // a[i+1]*b[i+1]
		VPSUBW(t[1], b[1], b[1]) // a[i]*b[i]
		VPSUBW(t[2], a[0], a[0]) // a[i]*b[i+1]
		VPSUBW(t[3], a[1], a[1]) // a[i+1]*b[i]

		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (25 + j*2)}, zl)
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (25 + j*2 + 1)}, zh)

		// Compute p0 = montReduce(int32(p0) * zeta) + p2
		VPMULLW(b[0], zl, t[0])
		VPMULHW(b[0], zh, b[0])
		VPMULHW(t[0], q, t[0])
		VPSUBW(t[0], b[0], b[0])
		VPADDW(b[0], b[1], b[0])

		// p1
		VPADDW(a[0], a[1], b[1])

		// Now the same but then for the next two
		VPMULLW(a[3], b[3], t[0])
		VPMULLW(a[2], b[2], t[1])
		VPMULLW(a[2], b[3], t[2])
		VPMULLW(a[3], b[2], t[3])

		VPMULLW(t[0], qinv, t[0])
		VPMULLW(t[1], qinv, t[1])
		VPMULLW(t[2], qinv, t[2])
		VPMULLW(t[3], qinv, t[3])

		// zl and zh are used as temporary registers here
		VPMULHW(a[3], b[3], zl) // will end up in b[2]
		VPMULHW(a[2], b[2], zh) // will end up in b[3]
		VPMULHW(a[2], b[3], a[2])
		VPMULHW(a[3], b[2], a[3])
		VMOVDQA(zl, b[2])
		VMOVDQA(zh, b[3])

		VPMULHW(t[0], q, t[0])
		VPMULHW(t[1], q, t[1])
		VPMULHW(t[2], q, t[2])
		VPMULHW(t[3], q, t[3])

		VPSUBW(t[0], b[2], b[2]) // a[i+1]*b[i+1]
		VPSUBW(t[1], b[3], b[3]) // a[i]*b[i]
		VPSUBW(t[2], a[2], a[2]) // a[i]*b[i+1]
		VPSUBW(t[3], a[3], a[3]) // a[i+1]*b[i]

		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (25 + j*2)}, zl)
		VMOVDQU(Mem{Base: zetasPtr, Disp: 32 * (25 + j*2 + 1)}, zh)

		// Compute p0 = p2 - montReduce(int32(p0) * zeta)
		VPMULLW(b[2], zl, t[0])
		VPMULHW(b[2], zh, b[2])
		VPMULHW(t[0], q, t[0])
		VPSUBW(t[0], b[2], b[2])
		VPSUBW(b[2], b[3], b[2])

		// p1
		VPADDW(a[2], a[3], b[3])

		for i := 0; i < 4; i++ {
			VMOVDQU(b[i], Mem{Base: pPtr, Disp: 32 * (4*j + i)})
		}
	}

	RET()
}

func tangleAVX2() {
	TEXT("tangleAVX2", NOSPLIT, "func(p *[256]int16)")
	Pragma("noescape")
	pPtr := Load(Param("p"), GP64())

	var xs [8]VecVirtual
	for i := 0; i < 8; i++ {
		xs[i] = YMM()
	}
	t := YMM()

	for offset := 0; offset < 2; offset++ {
		for i := 0; i < 8; i++ {
			VMOVDQU(Mem{Base: pPtr, Disp: 32 * (i + offset*8)}, xs[i])
		}

		bitflip(3, xs[0], xs[2], t)
		bitflip(3, xs[1], xs[3], t)
		bitflip(3, xs[4], xs[6], t)
		bitflip(3, xs[5], xs[7], t)

		bitflip(2, xs[0], xs[1], t)
		bitflip(2, xs[2], xs[3], t)
		bitflip(2, xs[4], xs[5], t)
		bitflip(2, xs[6], xs[7], t)

		bitflip(1, xs[0], xs[2], t)
		bitflip(1, xs[1], xs[3], t)
		bitflip(1, xs[4], xs[6], t)
		bitflip(1, xs[5], xs[7], t)

		bitflip(0, xs[0], xs[1], t)
		bitflip(0, xs[2], xs[3], t)
		bitflip(0, xs[4], xs[5], t)
		bitflip(0, xs[6], xs[7], t)

		for i := 0; i < 8; i++ {
			VMOVDQU(xs[i], Mem{Base: pPtr, Disp: 32 * (i + offset*8)})
		}
	}

	RET()
}

func detangleAVX2() {
	TEXT("detangleAVX2", NOSPLIT, "func(p *[256]int16)")
	Pragma("noescape")
	pPtr := Load(Param("p"), GP64())

	var xs [8]VecVirtual
	for i := 0; i < 8; i++ {
		xs[i] = YMM()
	}
	t := YMM()

	for offset := 0; offset < 2; offset++ {
		for i := 0; i < 8; i++ {
			VMOVDQU(Mem{Base: pPtr, Disp: 32 * (i + offset*8)}, xs[i])
		}

		bitflip(0, xs[0], xs[1], t)
		bitflip(0, xs[2], xs[3], t)
		bitflip(0, xs[4], xs[5], t)
		bitflip(0, xs[6], xs[7], t)

		bitflip(1, xs[0], xs[2], t)
		bitflip(1, xs[1], xs[3], t)
		bitflip(1, xs[4], xs[6], t)
		bitflip(1, xs[5], xs[7], t)

		bitflip(2, xs[0], xs[1], t)
		bitflip(2, xs[2], xs[3], t)
		bitflip(2, xs[4], xs[5], t)
		bitflip(2, xs[6], xs[7], t)

		bitflip(3, xs[0], xs[2], t)
		bitflip(3, xs[1], xs[3], t)
		bitflip(3, xs[4], xs[6], t)
		bitflip(3, xs[5], xs[7], t)

		for i := 0; i < 8; i++ {
			VMOVDQU(xs[i], Mem{Base: pPtr, Disp: 32 * (i + offset*8)})
		}
	}

	RET()
}

func barrettReduceAVX2() {
	TEXT("barrettReduceAVX2", NOSPLIT, "func(p *[256]int16)")
	Pragma("noescape")
	pPtr := Load(Param("p"), GP64())

	xs := [4]Op{YMM(), YMM(), YMM(), YMM()}
	ts := [4]Op{YMM(), YMM(), YMM(), YMM()}
	num := YMM()
	q := YMM()

	broadcastImm16(params.Q, q)
	broadcastImm16(20159, num)

	for offset := 0; offset < 4; offset++ {
		for i := 0; i < 4; i++ {
			VMOVDQU(Mem{Base: pPtr, Disp: 32 * (i + offset*4)}, xs[i])
		}

		// Recall that the Barrett reduction of x is given by
		//
		//  x - int16((int32(x)*20159)>>26)*q

		VPMULHW(num, xs[0], ts[0]) // t := (int32(x) * 20159) >> 16
		VPMULHW(num, xs[1], ts[1])
		VPMULHW(num, xs[2], ts[2])
		VPMULHW(num, xs[3], ts[3])

		// t = int16(t)>>10 so that t = (int32(x)*20159) >> 26
		VPSRAW(U8(10), ts[0], ts[0])
		VPSRAW(U8(10), ts[1], ts[1])
		VPSRAW(U8(10), ts[2], ts[2])
		VPSRAW(U8(10), ts[3], ts[3])

		VPMULLW(q, ts[0], ts[0]) // t *= q
		VPMULLW(q, ts[1], ts[1])
		VPMULLW(q, ts[2], ts[2])
		VPMULLW(q, ts[3], ts[3])

		VPSUBW(ts[0], xs[0], xs[0]) // x -= t
		VPSUBW(ts[1], xs[1], xs[1])
		VPSUBW(ts[2], xs[2], xs[2])
		VPSUBW(ts[3], xs[3], xs[3])

		for i := 0; i < 4; i++ {
			VMOVDQU(xs[i], Mem{Base: pPtr, Disp: 32 * (i + offset*4)})
		}
	}

	RET()
}

func normalizeAVX2() {
	TEXT("normalizeAVX2", NOSPLIT, "func(p *[256]int16)")
	Pragma("noescape")
	pPtr := Load(Param("p"), GP64())

	xs := [4]Op{YMM(), YMM(), YMM(), YMM()}
	ts := [4]Op{YMM(), YMM(), YMM(), YMM()}
	num := YMM()
	q := YMM()

	broadcastImm16(params.Q, q)
	broadcastImm16(20159, num)

	for offset := 0; offset < 4; offset++ {
		for i := 0; i < 4; i++ {
			VMOVDQU(Mem{Base: pPtr, Disp: 32 * (i + offset*4)}, xs[i])
		}

		// Just like the generic implementation, we do a Barrett reduction
		// followed by a conditional subtraction.

		// Recall that the Barrett reduction of x is given by
		//
		//  x - int16((int32(x)*20159)>>26)*q

		VPMULHW(num, xs[0], ts[0]) // t := (int32(x) * 20159) >> 16
		VPMULHW(num, xs[1], ts[1])
		VPMULHW(num, xs[2], ts[2])
		VPMULHW(num, xs[3], ts[3])

		// t = int16(t)>>10 so that t = (int32(x)*20159) >> 26
		VPSRAW(U8(10), ts[0], ts[0])
		VPSRAW(U8(10), ts[1], ts[1])
		VPSRAW(U8(10), ts[2], ts[2])
		VPSRAW(U8(10), ts[3], ts[3])

		VPMULLW(q, ts[0], ts[0]) // t *= q
		VPMULLW(q, ts[1], ts[1])
		VPMULLW(q, ts[2], ts[2])
		VPMULLW(q, ts[3], ts[3])

		VPSUBW(ts[0], xs[0], xs[0]) // x -= t
		VPSUBW(ts[1], xs[1], xs[1])
		VPSUBW(ts[2], xs[2], xs[2])
		VPSUBW(ts[3], xs[3], xs[3])

		// x is now Barrett reduced.  Next we conditionally subtract q to
		// normalize it.
		//
		//  x -= Q
		//  x += (x >> 15) & Q

		VPSUBW(q, xs[0], xs[0]) // x -= q
		VPSUBW(q, xs[1], xs[1])
		VPSUBW(q, xs[2], xs[2])
		VPSUBW(q, xs[3], xs[3])

		VPSRAW(U8(15), xs[0], ts[0]) // t := x >> 15
		VPSRAW(U8(15), xs[1], ts[1])
		VPSRAW(U8(15), xs[2], ts[2])
		VPSRAW(U8(15), xs[3], ts[3])

		VPAND(ts[0], q, ts[0]) // t &= q
		VPAND(ts[1], q, ts[1])
		VPAND(ts[2], q, ts[2])
		VPAND(ts[3], q, ts[3])

		VPADDW(xs[0], ts[0], xs[0]) // x += t
		VPADDW(xs[1], ts[1], xs[1])
		VPADDW(xs[2], ts[2], xs[2])
		VPADDW(xs[3], ts[3], xs[3])

		for i := 0; i < 4; i++ {
			VMOVDQU(xs[i], Mem{Base: pPtr, Disp: 32 * (i + offset*4)})
		}
	}

	RET()
}

func main() {
	ConstraintExpr("amd64")

	addAVX2()
	subAVX2()
	nttAVX2()
	invNttAVX2()
	mulHatAVX2()
	detangleAVX2()
	tangleAVX2()
	barrettReduceAVX2()
	normalizeAVX2()

	Generate()
}
