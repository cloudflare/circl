//go:generate go run src.go -out ../amd64.s -stubs ../stubs_amd64.go -pkg common

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
// XXX ensure Zetas and InvZetas are 16 byte aligned

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
//   a[0b0100] <--> b[0b0000]    a[0b0101] <--> b[0b0001]
//   a[0b0110] <--> b[0b0010]    a[0b0111] <--> b[0b0011]
//   a[0b1100] <--> b[0b1000]    a[0b1101] <--> b[0b1001]
//   a[0b1110] <--> b[0b1010]    a[0b1111] <--> b[0b1011]
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

func nttAVX2() {
	// We perform alost the same operations as the generic implementation of NTT,
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
	//  http://westerbaan.name/~bas/images/kyberavx2.svg.gz
	//
	// (XXX #167: put this image under a Cloudflare repo.)
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

		// XXX We're putting the coefficients back in their regular form
		//     until we have an AVX2 optimized MulHat(), Pack(),  InvNTT(),
		//     etc.

		bitflip(0, xs[0], xs[1], ts[0])
		bitflip(0, xs[2], xs[3], ts[0])
		bitflip(0, xs[4], xs[5], ts[0])
		bitflip(0, xs[6], xs[7], ts[0])

		bitflip(1, xs[0], xs[2], ts[0])
		bitflip(1, xs[1], xs[3], ts[0])
		bitflip(1, xs[4], xs[6], ts[0])
		bitflip(1, xs[5], xs[7], ts[0])

		bitflip(2, xs[0], xs[1], ts[0])
		bitflip(2, xs[2], xs[3], ts[0])
		bitflip(2, xs[4], xs[5], ts[0])
		bitflip(2, xs[6], xs[7], ts[0])

		bitflip(3, xs[0], xs[2], ts[0])
		bitflip(3, xs[1], xs[3], ts[0])
		bitflip(3, xs[4], xs[6], ts[0])
		bitflip(3, xs[5], xs[7], ts[0])

		for i := 0; i < 8; i++ {
			VMOVDQU(xs[i], Mem{Base: pPtr, Disp: 32 * (i + offset*8)})
		}
	}

	RET()
}

func main() {
	ConstraintExpr("amd64")

	addAVX2()
	subAVX2()
	nttAVX2()

	Generate()
}
