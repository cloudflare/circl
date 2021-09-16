//go:generate go run src.go -out ../amd64.s -stubs ../stubs_amd64.go -pkg common

// AVX2 optimized version of Poly.[Inv]NTT().  See the comments on the generic
// implementation for details on the maths involved.
package main

import (
	. "github.com/mmcloughlin/avo/build"   // nolint:golint,stylecheck
	. "github.com/mmcloughlin/avo/operand" // nolint:golint,stylecheck
	. "github.com/mmcloughlin/avo/reg"     // nolint:golint,stylecheck

	"github.com/cloudflare/circl/sign/dilithium/internal/common/params"
)

// XXX align Poly on 16 bytes such that we can use aligned moves
// XXX ensure Zetas and InvZetas are 16 byte aligned.

func broadcastImm32(c uint32, out Op) {
	tmp1 := GP32()
	tmp2 := XMM()
	MOVL(U32(c), tmp1)
	VMOVD(tmp1, tmp2)
	VPBROADCASTD(tmp2, out)
}

// Performs AND with an 64b immediate.
func andImm64(c uint64, inout Op) {
	tmp := GP64()
	MOVQ(U64(c), tmp)
	ANDQ(tmp, inout)
}

// Executes the permutation (a[2] b[0]) (a[3] b[1]) when considering only the
// even positions of a and b seen as [8]uint32.
func swapInner(a, b Op) {
	tmp := YMM()
	VPERM2I128(U8(32), b, a, tmp) // 0 + 2*16
	VPERM2I128(U8(49), b, a, b)   // 1 + 3*16
	VMOVDQA(tmp, a)
}

// Executes the permutation (a[1] b[0]) (a[3] b[2]) when considering only the
// even positions of a and b seen as [8]uint32.
func oddCrossing(a, b Op) {
	tmp := YMM()
	VPUNPCKLQDQ(b, a, tmp)
	VPUNPCKHQDQ(b, a, b)
	VMOVDQA(tmp, a)
}

// nolint:funlen
func nttAVX2() {
	// We perform the same operations as the generic implementation of NTT,
	// but use AVX2 to perform 16 butterflies at the same time.  For the
	// first few levels this is straight forward.  For the final levels we
	// need to move some coefficients around to be able to use the AVX2
	// instructions.

	TEXT("nttAVX2", 0, "func(p *[256]uint32)")
	Pragma("noescape")
	pPtr := Load(Param("p"), GP64())
	zetasPtr := GP64()
	LEAQ(NewDataAddr(Symbol{Name: "·Zetas"}, 0), zetasPtr)

	// We allocate a [256]uint64 on the stack aligned to 32 bytes to hold
	// "buf" which contains intermediate coefficients like "p" in the generic
	// algorithm, but then in uint64s instead of uint32s.
	bufPtr := GP64()
	LEAQ(AllocLocal(256*8+32), bufPtr) // +32 to be able to align

	andImm64(0xffffffffffffffe0, bufPtr)

	q := YMM()
	broadcastImm32(params.Q, q)
	doubleQ := YMM()
	broadcastImm32(2*params.Q, doubleQ)
	qinv := YMM()
	broadcastImm32(params.Qinv, qinv) // 4236238847 = -(q^-1) mod 2³²

	// Computes 4x4 Cooley--Tukey butterflies (a,b) ↦ (a + ζb, a - ζb).
	ctButterfly := func(a1, b1, zeta1, a2, b2, zeta2, a3, b3, zeta3,
		a4, b4, zeta4 Op) {
		t := [4]Op{YMM(), YMM(), YMM(), YMM()}
		a := [4]Op{a1, a2, a3, a4}
		b := [4]Op{b1, b2, b3, b4}
		zeta := [4]Op{zeta1, zeta2, zeta3, zeta4}

		// Set b = bζ.
		for i := 0; i < 4; i++ {
			VPMULUDQ(b[i], zeta[i], b[i])
		}

		// Now we reduce b below 2Q with the method of reduceLe2Q():
		//
		//      t := ((b * 4236238847) & 0xffffffff) * uint64(Q)
		//      return uint32((b + t) >> 32)
		for i := 0; i < 4; i++ {
			// t = b * 4236238847.
			VPMULUDQ(qinv, b[i], t[i])
		}

		// t = (t & 0xffffffff) * Q.  The and is implicit as VPMULUDQ
		// is a parallel 32b x 32b -> 64b multiplication.
		for i := 0; i < 4; i++ {
			VPMULUDQ(q, t[i], t[i])
		}

		// t = b + t
		for i := 0; i < 4; i++ {
			VPADDQ(t[i], b[i], t[i])
		}

		// t = t >> 32
		for i := 0; i < 4; i++ {
			VPSRLQ(U8(32), t[i], t[i])
		}

		// b = a + 2Q
		for i := 0; i < 4; i++ {
			VPADDD(a[i], doubleQ, b[i])
		}

		// a += t
		for i := 0; i < 4; i++ {
			VPADDD(t[i], a[i], a[i])
		}

		// b = b - t
		for i := 0; i < 4; i++ {
			VPSUBD(t[i], b[i], b[i])
		}
	}

	zs := [4]Op{YMM(), YMM(), YMM(), YMM()}
	var xs [8]VecVirtual
	for i := 0; i < 8; i++ {
		xs[i] = YMM()
	}

	// With AVX2 we can compute 4*4 Cooley--Tukey butterflies at the same time.
	// As loading and storing from memory is expensive, we try to compute
	// as much at the same time.

	// First, second and third level.
	// The first butterfly at the third level is (0, 32).  To compute it, we
	// need to compute some butterflies on the second level and in turn
	// the butterflies (0, 128), (32, 160), (64, 192) and (96, 224) on the
	// first level.  As we need to compute them anyway, we compute the
	// butterflies (0, 32), (64, 96), (128, 160) and (192, 224) on the
	// third level at the same time.  Using the uint64x4 AVX2 registers,
	// we compute (0, 32), (1, 33), ..., (4, 36), (64, 96), (64, 97), ...
	// in one go.  This is one eighth of the third level.  We repeat another
	// seven times with a shifted offset to compute the third level.

	// XXX should we really unroll this loop?
	for offset := 0; offset < 8; offset++ {
		// First level.
		// Load the coefficients.  First uint32s of xs[0], xs[1], ...
		// contains p[0], p[32], p[64], ..., p[224].
		for i := 0; i < 8; i++ {
			// Loads 4 32b coefficients at the same time; zeropads them to 64b
			// and puts them in xs[i].
			VPMOVZXDQ(Mem{Base: pPtr, Disp: 4 * (32*i + 4*offset)}, xs[i])
		}

		// XXX At the moment we've completely unrolled, so we could, if we want,
		//     hardcode the Zetas here instead of looking them up from memory.
		//     Is that worth it?

		VPBROADCASTD(Mem{Base: zetasPtr, Disp: 1 * 4}, zs[0]) // Zetas[1]

		ctButterfly(
			xs[0], xs[4], zs[0],
			xs[1], xs[5], zs[0],
			xs[2], xs[6], zs[0],
			xs[3], xs[7], zs[0],
		)

		// Second level
		VPBROADCASTD(Mem{Base: zetasPtr, Disp: 2 * 4}, zs[0]) // Zetas[2]
		VPBROADCASTD(Mem{Base: zetasPtr, Disp: 3 * 4}, zs[1]) // Zetas[3]

		ctButterfly(
			xs[0], xs[2], zs[0],
			xs[1], xs[3], zs[0],
			xs[4], xs[6], zs[1],
			xs[5], xs[7], zs[1],
		)

		// Third level
		VPBROADCASTD(Mem{Base: zetasPtr, Disp: 4 * 4}, zs[0]) // Zetas[4]
		VPBROADCASTD(Mem{Base: zetasPtr, Disp: 5 * 4}, zs[1]) // Zetas[5]
		VPBROADCASTD(Mem{Base: zetasPtr, Disp: 6 * 4}, zs[2]) // Zetas[6]
		VPBROADCASTD(Mem{Base: zetasPtr, Disp: 7 * 4}, zs[3]) // Zetas[7]

		ctButterfly(
			xs[0], xs[1], zs[0],
			xs[2], xs[3], zs[1],
			xs[4], xs[5], zs[2],
			xs[6], xs[7], zs[3],
		)

		for i := 0; i < 8; i++ {
			VMOVDQA(xs[i], Mem{Base: bufPtr, Disp: 8 * (32*i + 4*offset)})
		}
	}

	// Fourth, fifth, sixth, seventh and eighth level.
	// If we want to compute the butterfly (0, 1) in the eighth level, we need
	// to compute the first 2 butterflies in the seventh level; the first 4
	// of the sixth, ... and the first 16 in the fourth level which needs the
	// first 32 coefficients already computed in the third level.
	// Going forward again, we see that we can use these to compute the first
	// 32 coefficients.  As each level requires 16 butterflies, we can
	// conveniently perform these all in our YMM registers.
	// After that we repeat the same method for the next 32 coefficients and
	// continue for a total of eight times to finish the computation of
	// the NTT.

	// XXX should we really unroll this loop?
	for offset := 0; offset < 8; offset++ {
		// Load the first 32 coefficients from level 3.  Recall that bufPtr
		// has 64 bits of space for each coefficient.
		for i := 0; i < 8; i++ {
			VMOVDQA(Mem{Base: bufPtr, Disp: 8 * 4 * (8*offset + i)}, xs[i])
		}

		// Fourth level
		VPBROADCASTD(Mem{Base: zetasPtr, Disp: (8 + offset) * 4}, zs[0])
		ctButterfly(
			xs[0], xs[4], zs[0],
			xs[1], xs[5], zs[0],
			xs[2], xs[6], zs[0],
			xs[3], xs[7], zs[0],
		)

		// Fifth level
		VPBROADCASTD(Mem{Base: zetasPtr, Disp: (16 + offset*2) * 4}, zs[0])
		VPBROADCASTD(Mem{Base: zetasPtr, Disp: (16 + offset*2 + 1) * 4}, zs[1])
		ctButterfly(
			xs[0], xs[2], zs[0],
			xs[1], xs[3], zs[0],
			xs[4], xs[6], zs[1],
			xs[5], xs[7], zs[1],
		)

		// Sixth level
		for i := 0; i < 4; i++ {
			VPBROADCASTD(Mem{Base: zetasPtr, Disp: (32 + offset*4 + i) * 4}, zs[i])
		}
		ctButterfly(
			xs[0], xs[1], zs[0],
			xs[2], xs[3], zs[1],
			xs[4], xs[5], zs[2],
			xs[6], xs[7], zs[3],
		)

		// Seventh level
		// Now things get a bit trickier.  We have to compute the butterflies
		// (0, 2), (1, 3), (4, 6), (5, 7), etc which don't fit our ctButterfly()
		// routine, which likes to have four consecutive butterflies.
		// To work around this, we swap 2 with 4 and 3 with 5, etc., which
		// allows us to use our old routine.

		tmp := YMM()
		// XXX optimize?  We might want to add a small extra table for just
		//     these zetas so that we don't have to blend them.
		for i := 0; i < 4; i++ {
			VPBROADCASTD(Mem{Base: zetasPtr, Disp: (64 + offset*8 + i*2) * 4}, tmp)
			VPBROADCASTD(Mem{Base: zetasPtr, Disp: (64 + offset*8 + i*2 + 1) * 4}, zs[i])
			VPBLENDD(U8(240), zs[i], tmp, zs[i])
		}

		swapInner(xs[0], xs[1])
		swapInner(xs[2], xs[3])
		swapInner(xs[4], xs[5])
		swapInner(xs[6], xs[7])

		ctButterfly(
			xs[0], xs[1], zs[0],
			xs[2], xs[3], zs[1],
			xs[4], xs[5], zs[2],
			xs[6], xs[7], zs[3],
		)

		// Eighth level
		// Finally, we have to perform the butterflies (0, 1), (2, 3), etc.
		// Swapping 1 with 4 and 3 with 6 (etc.) will ensure that a
		// straight-forward call to our ctButterfly() routine will do the right
		// thing.
		oddCrossing(xs[0], xs[1])
		oddCrossing(xs[2], xs[3])
		oddCrossing(xs[4], xs[5])
		oddCrossing(xs[6], xs[7])

		for i := 0; i < 4; i++ {
			VPMOVZXDQ(Mem{Base: zetasPtr, Disp: (128 + 4*i + offset*16) * 4}, zs[i])
		}

		ctButterfly(
			xs[0], xs[1], zs[0],
			xs[2], xs[3], zs[1],
			xs[4], xs[5], zs[2],
			xs[6], xs[7], zs[3],
		)

		// Packing.
		// Due to swapInner() and oddCrossing() our coefficients are laid out
		// as 0, 2, 4, 6, 1, 3, 5, 7, 8, 10, ... in xs[0], xs[1], ...
		// with junk 32b in between.  By shifting the odd xss 32b to the
		// left and merging them with the even xss, we get the desired
		// order 0, 1, 2, 3, ... without any padding, which can then be
		// moved out into memory.

		VPSLLQ(U8(32), xs[1], xs[1])
		VPSLLQ(U8(32), xs[3], xs[3])
		VPSLLQ(U8(32), xs[5], xs[5])
		VPSLLQ(U8(32), xs[7], xs[7])

		VPBLENDD(U8(170), xs[1], xs[0], xs[0])
		VPBLENDD(U8(170), xs[3], xs[2], xs[2])
		VPBLENDD(U8(170), xs[5], xs[4], xs[4])
		VPBLENDD(U8(170), xs[7], xs[6], xs[6])

		for i := 0; i < 4; i++ {
			VMOVDQU(xs[2*i], Mem{Base: pPtr, Disp: 8 * 4 * (4*offset + i)})
		}
	}

	RET()
}

// nolint:funlen
func invNttAVX2() {
	// Just like with the generic implementation, we do the operations of
	// NTT in reverse, except for two things: we hoist out all divisions by
	// two from the Gentleman-Sande butterflies and accumulate them to one
	// big division by 2⁸ at the end.
	TEXT("invNttAVX2", 0, "func(p *[256]uint32)")
	Pragma("noescape")
	pPtr := Load(Param("p"), GP64())
	zetasPtr := GP64()
	LEAQ(NewDataAddr(Symbol{Name: "·InvZetas"}, 0), zetasPtr)

	// We allocate a [256]uint64 on the stack aligned to 32 bytes to hold
	// "buf" which contains intermediate coefficients like "p" in the generic
	// algorithm, but then in uint64s instead of uint32s.
	bufPtr := GP64()
	LEAQ(AllocLocal(256*8+32), bufPtr) // +32 to be able to align
	andImm64(0xffffffffffffffe0, bufPtr)

	q := YMM()
	broadcastImm32(params.Q, q)
	q256 := YMM()
	broadcastImm32(256*params.Q, q256)
	qinv := YMM()
	broadcastImm32(params.Qinv, qinv)

	// Computes 4x4 doubled Gentleman--Sande butterflies (a,b) ↦ (a+b, ζ(a-b)).
	gsButterfly := func(a1, b1, zeta1, a2, b2, zeta2, a3, b3, zeta3,
		a4, b4, zeta4 Op) {
		t := [4]Op{YMM(), YMM(), YMM(), YMM()}
		a := [4]Op{a1, a2, a3, a4}
		b := [4]Op{b1, b2, b3, b4}
		zeta := [4]Op{zeta1, zeta2, zeta3, zeta4}

		// XXX be more parallel when we have more registers available, when
		//     we don't use the full four registers for zetas.
		for i := 0; i < 4; i++ {
			// Set t = 256Q + a in preparation of subtracting b
			VPADDD(a[i], q256, t[i])

			// Set t = t - b
			VPSUBD(b[i], t[i], t[i])

			// Set a = a + b
			VPADDD(a[i], b[i], a[i])

			// Set b = tζ
			VPMULUDQ(t[i], zeta[i], b[i])
		}

		// Now we reduce b below 2Q with the method of reduceLe2Q():
		//
		//      t := ((b * 4236238847) & 0xffffffff) * uint64(Q)
		//      return uint32((b + t) >> 32)
		for i := 0; i < 4; i++ {
			// t = b * 4236238847.
			VPMULUDQ(qinv, b[i], t[i])
		}

		// t = (t & 0xffffffff) * Q.  The and is implicit as VPMULUDQ
		// is a parallel 32b x 32b -> 64b multiplication.
		for i := 0; i < 4; i++ {
			VPMULUDQ(q, t[i], t[i])
		}

		// t = b + t
		for i := 0; i < 4; i++ {
			VPADDQ(t[i], b[i], t[i])
		}

		// b = t >> 32
		for i := 0; i < 4; i++ {
			VPSRLQ(U8(32), t[i], b[i])
		}
	}

	zs := [4]Op{YMM(), YMM(), YMM(), YMM()}
	var xs [8]VecVirtual
	for i := 0; i < 8; i++ {
		xs[i] = YMM()
	}

	// XXX should we really unroll this loop?
	for offset := 0; offset < 8; offset++ {
		// Load coeffs 0 1 2 3 4 5 6 7 into xs[0], 8 ... 16 into xs[1], etc.
		for i := 0; i < 4; i++ {
			VMOVDQU(Mem{Base: pPtr, Disp: 8 * 4 * (4*offset + i)}, xs[2*i])
		}

		// Move odd coeffs of xs[2*i] into xs[2*i+1] and shift down.  Ignoring
		// the odd coefficients, we have 0 2 4 6 in xs[0] and 1 3 4 5 in xs[1].
		for i := 0; i < 4; i++ {
			VPSRLQ(U8(32), xs[2*i], xs[2*i+1])
		}

		// Eighth level
		for i := 0; i < 4; i++ {
			VPMOVZXDQ(Mem{Base: zetasPtr, Disp: 4 * 4 * (4*offset + i)}, zs[i])
		}

		gsButterfly(
			xs[0], xs[1], zs[0],
			xs[2], xs[3], zs[1],
			xs[4], xs[5], zs[2],
			xs[6], xs[7], zs[3],
		)

		// See comments in nttAVX2() above about oddCrossing() and swapInner().
		oddCrossing(xs[0], xs[1])
		oddCrossing(xs[2], xs[3])
		oddCrossing(xs[4], xs[5])
		oddCrossing(xs[6], xs[7])

		// Seventh level
		tmp := YMM()
		// XXX optimize?  We might want to add a small extra table for just
		//     these zetas so that we don't have to blend them.
		for i := 0; i < 4; i++ {
			VPBROADCASTD(Mem{Base: zetasPtr, Disp: (128 + offset*8 + i*2) * 4}, tmp)
			VPBROADCASTD(Mem{Base: zetasPtr, Disp: (128 + offset*8 + i*2 + 1) * 4}, zs[i])
			VPBLENDD(U8(240), zs[i], tmp, zs[i])
		}

		gsButterfly(
			xs[0], xs[1], zs[0],
			xs[2], xs[3], zs[1],
			xs[4], xs[5], zs[2],
			xs[6], xs[7], zs[3],
		)

		// See comments in nttAVX2() above about oddCrossing() and swapInner()
		swapInner(xs[0], xs[1])
		swapInner(xs[2], xs[3])
		swapInner(xs[4], xs[5])
		swapInner(xs[6], xs[7])

		// Sixth level
		for i := 0; i < 4; i++ {
			VPBROADCASTD(Mem{Base: zetasPtr, Disp: (192 + offset*4 + i) * 4}, zs[i])
		}

		gsButterfly(
			xs[0], xs[1], zs[0],
			xs[2], xs[3], zs[1],
			xs[4], xs[5], zs[2],
			xs[6], xs[7], zs[3],
		)

		// Fifth level
		VPBROADCASTD(Mem{Base: zetasPtr, Disp: (224 + offset*2) * 4}, zs[0])
		VPBROADCASTD(Mem{Base: zetasPtr, Disp: (224 + offset*2 + 1) * 4}, zs[1])

		gsButterfly(
			xs[0], xs[2], zs[0],
			xs[1], xs[3], zs[0],
			xs[4], xs[6], zs[1],
			xs[5], xs[7], zs[1],
		)

		// Fourth level
		VPBROADCASTD(Mem{Base: zetasPtr, Disp: (240 + offset) * 4}, zs[0])

		gsButterfly(
			xs[0], xs[4], zs[0],
			xs[1], xs[5], zs[0],
			xs[2], xs[6], zs[0],
			xs[3], xs[7], zs[0],
		)

		for i := 0; i < 8; i++ {
			VMOVDQA(xs[i], Mem{Base: bufPtr, Disp: 8 * 4 * (8*offset + i)})
		}
	}

	// XXX should we really unroll this loop?
	for offset := 0; offset < 8; offset++ {
		for i := 0; i < 8; i++ {
			VMOVDQA(Mem{Base: bufPtr, Disp: 8 * (32*i + 4*offset)}, xs[i])
		}

		// Third level
		VPBROADCASTD(Mem{Base: zetasPtr, Disp: (248 * 4)}, zs[0])
		VPBROADCASTD(Mem{Base: zetasPtr, Disp: (249 * 4)}, zs[1])
		VPBROADCASTD(Mem{Base: zetasPtr, Disp: (250 * 4)}, zs[2])
		VPBROADCASTD(Mem{Base: zetasPtr, Disp: (251 * 4)}, zs[3])

		gsButterfly(
			xs[0], xs[1], zs[0],
			xs[2], xs[3], zs[1],
			xs[4], xs[5], zs[2],
			xs[6], xs[7], zs[3],
		)

		// Second level
		VPBROADCASTD(Mem{Base: zetasPtr, Disp: (252 * 4)}, zs[0])
		VPBROADCASTD(Mem{Base: zetasPtr, Disp: (253 * 4)}, zs[1])

		gsButterfly(
			xs[0], xs[2], zs[0],
			xs[1], xs[3], zs[0],
			xs[4], xs[6], zs[1],
			xs[5], xs[7], zs[1],
		)

		// First level
		VPBROADCASTD(Mem{Base: zetasPtr, Disp: (254 * 4)}, zs[0])

		gsButterfly(
			xs[0], xs[4], zs[0],
			xs[1], xs[5], zs[0],
			xs[2], xs[6], zs[0],
			xs[3], xs[7], zs[0],
		)

		// Finally, we multiply by 41978 = (256)^-1 R² ...
		rOver256 := YMM()
		broadcastImm32(params.ROver256, rOver256)

		for i := 0; i < 8; i++ {
			VPMULUDQ(xs[i], rOver256, xs[i])
		}

		var t [8]VecVirtual
		// (we need this loop, otherwise we run out of YMM registers.)
		for j := 0; j <= 4; j += 4 {
			// ... and reduce below 2Q with the method of reduceLe2Q():
			//
			//      t := ((x * 4236238847) & 0xffffffff) * uint64(Q)
			//      return uint32((x + t) >> 32)
			for i := j; i < 4+j; i++ {
				t[i] = YMM()
				// t = x * 4236238847.
				VPMULUDQ(qinv, xs[i], t[i])
			}

			// t = (t & 0xffffffff) * Q.  The and is implicit as VPMULUDQ
			// is a parallel 32b x 32b -> 64b multiplication.
			for i := j; i < 4+j; i++ {
				VPMULUDQ(q, t[i], t[i])
			}

			// t = x + t
			for i := j; i < 4+j; i++ {
				VPADDQ(t[i], xs[i], t[i])
			}

			// x = t >> 32
			for i := j; i < 4+j; i++ {
				VPSRLQ(U8(32), t[i], xs[i])
			}
		}

		for i := 0; i < 8; i++ {
			VMOVDQA(xs[i], Mem{Base: bufPtr, Disp: 8 * (32*i + 4*offset)})
		}
	}

	// Finally, we copy the 32b results from the [256]uint64 buf to
	// the [256]uint32 p.
	// XXX is this the most efficient way?
	for j := 0; j < 8; j++ {
		for i := 0; i < 8; i++ {
			VMOVDQA(Mem{Base: bufPtr, Disp: 32 * (8*j + i)}, xs[i])
		}
		// Recall that oddCrossing after swapInner will permute the
		// even coefficients from 0 1 2 3 4 5 6 7 to 0 2 4 6 1 3 5 7 and so
		// then we can simply shift and blend the last four into the first four
		// as we did at the end of nttAVX2().
		for i := 0; i < 4; i++ {
			swapInner(xs[2*i], xs[2*i+1])
		}
		for i := 0; i < 4; i++ {
			oddCrossing(xs[2*i], xs[2*i+1])
		}
		for i := 0; i < 4; i++ {
			VPSLLQ(U8(32), xs[2*i+1], xs[2*i+1])
		}
		for i := 0; i < 4; i++ {
			VPBLENDD(U8(170), xs[2*i+1], xs[2*i], xs[2*i])
		}
		for i := 0; i < 4; i++ {
			VMOVDQU(xs[2*i], Mem{Base: pPtr, Disp: 32 * (4*j + i)})
		}
	}

	RET()
}

// XXX Split out into separate file.  To do this we need to figure out how
//     to share code properly between avo modules.
func mulHatAVX2() {
	TEXT("mulHatAVX2", NOSPLIT, "func(p, a, b *[256]uint32)")
	Pragma("noescape")
	pPtr := Load(Param("p"), GP64())
	aPtr := Load(Param("a"), GP64())
	bPtr := Load(Param("b"), GP64())

	q := YMM()
	broadcastImm32(params.Q, q)
	qinv := YMM()
	broadcastImm32(params.Qinv, qinv)

	var a [4]VecVirtual
	var b [4]VecVirtual
	for i := 0; i < 4; i++ {
		a[i] = YMM()
		b[i] = YMM()
	}

	// XXX Is this loop unrolling worthwhile?
	for j := 0; j < 16; j++ {
		// XXX We could use 6 registers each (instead of 4).  Does that make
		//     it faster?
		for i := 0; i < 4; i++ {
			VPMOVZXDQ(Mem{Base: aPtr, Disp: 16 * (4*j + i)}, a[i])
		}
		for i := 0; i < 4; i++ {
			VPMOVZXDQ(Mem{Base: bPtr, Disp: 16 * (4*j + i)}, b[i])
		}
		for i := 0; i < 4; i++ {
			VPMULUDQ(a[i], b[i], b[i])
		}

		// Now we reduce b below 2Q with the method of reduceLe2Q():
		//
		//      a := ((b * 4236238847) & 0xffffffff) * uint64(Q)
		//      return uint32((b + a) >> 32)
		for i := 0; i < 4; i++ {
			// a = b * 4236238847.
			VPMULUDQ(qinv, b[i], a[i])
		}

		// t = (t & 0xffffffff) * Q.  The and is implicit as VPMULUDQ
		// is a parallel 32b x 32b -> 64b multiplication.
		for i := 0; i < 4; i++ {
			VPMULUDQ(q, a[i], a[i])
		}

		// t = b + a
		for i := 0; i < 4; i++ {
			VPADDQ(a[i], b[i], a[i])
		}

		// b = a >> 32
		for i := 0; i < 4; i++ {
			VPSRLQ(U8(32), a[i], b[i])
		}

		// Pack into p.  See end of invNttAvx2() for a description of the method.
		// XXX is there a better way to do this that avoids the PERM
		//     in oddCrossing?
		for i := 0; i < 2; i++ {
			swapInner(b[2*i], b[2*i+1])
		}
		for i := 0; i < 2; i++ {
			oddCrossing(b[2*i], b[2*i+1])
		}
		for i := 0; i < 2; i++ {
			VPSLLQ(U8(32), b[2*i+1], b[2*i+1])
		}
		for i := 0; i < 2; i++ {
			VPBLENDD(U8(170), b[2*i+1], b[2*i], b[2*i])
		}
		for i := 0; i < 2; i++ {
			VMOVDQU(b[2*i], Mem{Base: pPtr, Disp: 32 * (2*j + i)})
		}
	}

	RET()
}

func addAVX2() {
	TEXT("addAVX2", NOSPLIT, "func(p, a, b *[256]uint32)")
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

	// XXX is unrolling worth it?
	for j := 0; j < 4; j++ {
		for i := 0; i < 8; i++ {
			VMOVDQU(Mem{Base: aPtr, Disp: 32 * (8*j + i)}, a[i])
		}
		for i := 0; i < 8; i++ {
			VMOVDQU(Mem{Base: bPtr, Disp: 32 * (8*j + i)}, b[i])
		}
		for i := 0; i < 8; i++ {
			VPADDD(a[i], b[i], b[i])
		}
		for i := 0; i < 8; i++ {
			VMOVDQU(b[i], Mem{Base: pPtr, Disp: 32 * (8*j + i)})
		}
	}

	RET()
}

func subAVX2() {
	TEXT("subAVX2", NOSPLIT, "func(p, a, b *[256]uint32)")
	Pragma("noescape")
	pPtr := Load(Param("p"), GP64())
	aPtr := Load(Param("a"), GP64())
	bPtr := Load(Param("b"), GP64())

	var a [4]VecVirtual
	var b [4]VecVirtual
	for i := 0; i < 4; i++ {
		a[i] = YMM()
		b[i] = YMM()
	}

	doubleQ := YMM()
	broadcastImm32(2*params.Q, doubleQ)

	// XXX is unrolling worth it?
	for j := 0; j < 8; j++ {
		for i := 0; i < 4; i++ {
			VMOVDQU(Mem{Base: aPtr, Disp: 32 * (4*j + i)}, a[i])
		}
		for i := 0; i < 4; i++ {
			VMOVDQU(Mem{Base: bPtr, Disp: 32 * (4*j + i)}, b[i])
		}
		for i := 0; i < 4; i++ {
			VPSUBD(b[i], doubleQ, b[i])
		}
		for i := 0; i < 4; i++ {
			VPADDD(a[i], b[i], b[i])
		}
		for i := 0; i < 4; i++ {
			VMOVDQU(b[i], Mem{Base: pPtr, Disp: 32 * (4*j + i)})
		}
	}

	RET()
}

func packLe16AVX2() {
	TEXT("packLe16AVX2", NOSPLIT, "func(p *[256]uint32, buf *byte)")
	Pragma("noescape")
	pPtr := Load(Param("p"), GP64())
	bufPtr := Load(Param("buf"), GP64())

	var a [8]VecVirtual
	var b [8]VecVirtual
	for i := 0; i < 8; i++ {
		a[i] = YMM()
		b[i] = YMM()
	}

	for j := 0; j < 4; j++ {
		// We load p[0], ..., p[7] into a[0], p[8], ..., p[15] into a[1], etc.,
		// so we may consider a as a matrix.  We transpose a in the usual way.
		for i := 0; i < 4; i++ {
			VMOVDQU(Mem{Base: pPtr, Disp: 32 * (8*j + 2*i)}, a[2*i])
			VPUNPCKLDQ(Mem{Base: pPtr, Disp: 32 * (8*j + 2*i + 1)},
				a[2*i], a[2*i])
			VMOVDQU(Mem{Base: pPtr, Disp: 32 * (8*j + 2*i)}, a[2*i+1])
			VPUNPCKHDQ(Mem{Base: pPtr, Disp: 32 * (8*j + 2*i + 1)},
				a[2*i+1], a[2*i+1])
		}

		VPUNPCKLQDQ(a[2], a[0], b[0])
		VPUNPCKHQDQ(a[2], a[0], b[1])
		VPUNPCKLQDQ(a[3], a[1], b[2])
		VPUNPCKHQDQ(a[3], a[1], b[3])
		VPUNPCKLQDQ(a[6], a[4], b[4])
		VPUNPCKHQDQ(a[6], a[4], b[5])
		VPUNPCKLQDQ(a[7], a[5], b[6])
		VPUNPCKHQDQ(a[7], a[5], b[7])

		VPERM2I128(U8(32), b[4], b[0], a[0])
		VPERM2I128(U8(32), b[5], b[1], a[1])
		VPERM2I128(U8(32), b[6], b[2], a[2])
		VPERM2I128(U8(32), b[7], b[3], a[3])
		VPERM2I128(U8(49), b[4], b[0], a[4])
		VPERM2I128(U8(49), b[5], b[1], a[5])
		VPERM2I128(U8(49), b[6], b[2], a[6])
		VPERM2I128(U8(49), b[7], b[3], a[7])

		// a has been transposed, so a[0] contains p[0], p[8], ... and
		// a[1] contains p[1], p[9], ..., etc.  We shift a[i] by 4*i to the left
		// and or them together.
		for i := 1; i < 8; i++ {
			VPSLLD(U8(4*i), a[i], a[i])
		}

		VPOR(a[0], a[1], a[1])
		VPOR(a[2], a[3], a[3])
		VPOR(a[4], a[5], a[5])
		VPOR(a[6], a[7], a[7])
		VPOR(a[1], a[3], a[3])
		VPOR(a[5], a[7], a[7])
		VPOR(a[3], a[7], a[7])

		VMOVDQU(a[7], Mem{Base: bufPtr, Disp: 32 * j})
	}

	RET()
}

func reduceLe2QAVX2() {
	TEXT("reduceLe2QAVX2", NOSPLIT, "func(p *[256]uint32)")
	Pragma("noescape")
	pPtr := Load(Param("p"), GP64())

	var a, b, c [4]VecVirtual
	for i := 0; i < 4; i++ {
		a[i] = YMM()
		b[i] = YMM()
		c[i] = YMM()
	}
	twoToThe23MinusOne := YMM()
	broadcastImm32((1<<23)-1, twoToThe23MinusOne)

	// We use the same computation as used in reduceLe2Q() for the separate
	// coefficients.
	for j := 0; j < 8; j++ {
		for i := 0; i < 4; i++ {
			VMOVDQU(Mem{Base: pPtr, Disp: 32 * (4*j + i)}, a[i])
		}

		// b = a >> 23
		for i := 0; i < 4; i++ {
			VPSRLD(U8(23), a[i], b[i])
		}

		// a = a & 2²³-1
		for i := 0; i < 4; i++ {
			VPAND(a[i], twoToThe23MinusOne, a[i])
		}

		// c = (b << 13) - b
		for i := 0; i < 4; i++ {
			VPSLLD(U8(13), b[i], c[i])
		}
		for i := 0; i < 4; i++ {
			VPSUBD(b[i], c[i], c[i])
		}

		// a = a + c
		for i := 0; i < 4; i++ {
			VPADDD(a[i], c[i], a[i])
		}

		// Write back
		for i := 0; i < 4; i++ {
			VMOVDQU(a[i], Mem{Base: pPtr, Disp: 32 * (4*j + i)})
		}
	}

	RET()
}

func le2qModQAVX2() {
	TEXT("le2qModQAVX2", NOSPLIT, "func(p *[256]uint32)")
	Pragma("noescape")
	pPtr := Load(Param("p"), GP64())

	// We use the same method as le2qModQ().
	var a, m [4]VecVirtual
	for i := 0; i < 4; i++ {
		a[i] = YMM()
		m[i] = YMM()
	}

	q := YMM()
	broadcastImm32(params.Q, q)

	for j := 0; j < 8; j++ {
		for i := 0; i < 4; i++ {
			VMOVDQU(Mem{Base: pPtr, Disp: 32 * (4*j + i)}, a[i])
		}

		// a -= Q
		for i := 0; i < 4; i++ {
			VPSUBD(q, a[i], a[i])
		}

		// m = uint32(int32(a) >> 31)
		for i := 0; i < 4; i++ {
			VPSRAD(U8(31), a[i], m[i])
		}

		// m &= q
		for i := 0; i < 4; i++ {
			VPAND(m[i], q, m[i])
		}

		// a += m
		for i := 0; i < 4; i++ {
			VPADDD(a[i], m[i], a[i])
		}

		for i := 0; i < 4; i++ {
			VMOVDQU(a[i], Mem{Base: pPtr, Disp: 32 * (4*j + i)})
		}
	}

	RET()
}

func exceedsAVX2() {
	TEXT("exceedsAVX2", NOSPLIT, "func(p *[256]uint32, bound uint32) uint8")
	Pragma("noescape")
	pPtr := Load(Param("p"), GP64())
	bound := Load(Param("bound"), GP32())

	var a, b [4]VecVirtual
	for i := 0; i < 4; i++ {
		a[i] = YMM()
		b[i] = YMM()
	}

	boundX4 := XMM()
	boundX8 := YMM()
	VMOVD(bound, boundX4)
	VPBROADCASTD(boundX4, boundX8)

	qMinusOneDiv2 := YMM()
	broadcastImm32((params.Q-1)/2, qMinusOneDiv2)

	signMaskX8 := YMM()
	broadcastImm32(0x80000000, signMaskX8)

	signsMask := GP32()
	MOVL(U32(0x88888888), signsMask)

	for j := 0; j < 8; j++ {
		for i := 0; i < 4; i++ {
			VMOVDQU(Mem{Base: pPtr, Disp: 32 * (4*j + i)}, a[i])
		}

		// We use the same method as Poly.exceedsGeneric().

		// a = (Q-1)/2 - a
		for i := 0; i < 4; i++ {
			VPSUBD(a[i], qMinusOneDiv2, a[i])
		}

		// b = a >> 31
		for i := 0; i < 4; i++ {
			VPSRAD(U8(31), a[i], b[i])
		}

		// a = a ^ b
		for i := 0; i < 4; i++ {
			VPXOR(a[i], b[i], a[i])
		}

		// a = (Q-1)/2 - a
		for i := 0; i < 4; i++ {
			VPSUBD(a[i], qMinusOneDiv2, a[i])
		}

		// Here exceedsGeneric() checks if a ⩾ bound.  We'll be more clever.
		// a ⩾ bound iff a - bound ⩾ 0, so set a = a - bound first.
		for i := 0; i < 4; i++ {
			VPSUBD(boundX8, a[i], a[i])
		}

		// a &= 0x80000000.  Leaves the sign.  Should be zero.
		for i := 0; i < 4; i++ {
			VPAND(a[i], signMaskX8, a[i])
		}

		for i := 0; i < 4; i++ {
			// Move the high bits, which are all zero except possibly for
			// the sign bits, into tmp.
			tmp := GP32()
			VPMOVMSKB(a[i], tmp)

			// If one of the sign bits is zero, then one of the as is
			// positive hence the bound is exceeded.
			XORL(signsMask, tmp) // 0b10001000100010001000100010001000
			TESTL(tmp, tmp)
			JNZ(LabelRef("exceeded"))
		}
	}

	ret := GP8()
	XORB(ret, ret)
	Store(ret, ReturnIndex(0))
	RET()

	Label("exceeded")
	MOVB(U8(1), ret)
	Store(ret, ReturnIndex(0))
	RET()
}

func mulBy2toDAVX2() {
	TEXT("mulBy2toDAVX2", NOSPLIT, "func(p, q *[256]uint32)")
	Pragma("noescape")
	pPtr := Load(Param("p"), GP64())
	qPtr := Load(Param("q"), GP64())

	var x [8]VecVirtual
	for i := 0; i < 8; i++ {
		x[i] = YMM()
	}

	for j := 0; j < 4; j++ {
		for i := 0; i < 8; i++ {
			VMOVDQU(Mem{Base: qPtr, Disp: 32 * (8*j + i)}, x[i])
		}
		for i := 0; i < 8; i++ {
			VPSLLD(U8(params.D), x[i], x[i])
		}
		for i := 0; i < 8; i++ {
			VMOVDQU(x[i], Mem{Base: pPtr, Disp: 32 * (8*j + i)})
		}
	}

	RET()
}


func main() {
	ConstraintExpr("amd64")

	nttAVX2()
	invNttAVX2()
	mulHatAVX2()
	addAVX2()
	subAVX2()
	packLe16AVX2()
	reduceLe2QAVX2()
	le2qModQAVX2()
	exceedsAVX2()
	mulBy2toDAVX2()

	Generate()
}
