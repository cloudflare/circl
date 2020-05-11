// +build ignore

// AVX2 optimized version of Poly.[Inv]NTT().  See the comments on the generic
// implementation for details on the maths involved.

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"

	"github.com/cloudflare/circl/sign/dilithium/internal/params"
)

// XXX align Poly on 16 bytes such that we can use aligned moves
// XXX ensure Zetas and InvZetas are 16 byte aligned.

func broadcast_imm32(c uint32, out Op) {
	tmp1 := GP32()
	tmp2 := XMM()
	MOVL(U32(c), tmp1)
	VMOVD(tmp1, tmp2)
	VPBROADCASTD(tmp2, out)
}

// Performs AND with an 64b immediate.
func and_imm64(c uint64, inout Op) {
	tmp := GP64()
	MOVQ(U64(c), tmp)
	ANDQ(tmp, inout)
}

// Executes the permutation (a[2] b[0]) (a[3] b[1]) when considering only the
// even positions of a and b seen as [8]uint32
func swapInner(a, b Op) {
	tmp := YMM()
	VPERM2I128(U8(32), b, a, tmp) // 0 + 2*16
	VPERM2I128(U8(49), b, a, b)   // 1 + 3*16
	VMOVDQA(tmp, a)
}

// Executes the permutation (a[1] b[0]) (a[3] b[2]) when considering only the
// even positions of a and b seen as [8]uint32
func oddCrossing(a, b Op) {
	tmp := YMM()
	VPUNPCKLQDQ(b, a, tmp)
	VPUNPCKHQDQ(b, a, b)
	VMOVDQA(tmp, a)
}

func nttAVX2() {
	// We perform the same operations as the generic implementation of NTT,
	// but use AVX2 to perform 16 butterflies at the same time.  For the
	// first few levels this is straight forward.  For the final levels we
	// need to move some coefficients around to be able to use the AVX2
	// instructions.

	TEXT("nttAVX2", 0, "func(p *[256]uint32)")
	Pragma("noescape")
	p_ptr := Load(Param("p"), GP64())
	zetas_ptr := GP64()
	LEAQ(NewDataAddr(Symbol{Name: "·Zetas"}, 0), zetas_ptr)

	// We allocate a [256]uint64 on the stack aligned to 32 bytes to hold
	// "buf" which contains intermediate coefficients like "p" in the generic
	// algorithm, but then in uint64s instead of uint32s.
	buf_ptr := GP64()
	LEAQ(AllocLocal(256*8+32), buf_ptr) // +32 to be able to align

	and_imm64(0xffffffffffffffe0, buf_ptr)

	q := YMM()
	broadcast_imm32(params.Q, q)
	doubleQ := YMM()
	broadcast_imm32(2*params.Q, doubleQ)
	qinv := YMM()
	broadcast_imm32(params.Qinv, qinv) // 4236238847 = -(q^-1) mod 2^32

	// Computes 4x4 Cooley--Tukey butterflies (a,b) |-> (a + ζb, a - ζb).
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
			VPMOVZXDQ(Mem{Base: p_ptr, Disp: 4 * (32*i + 4*offset)}, xs[i])
		}

		// XXX At the moment we've completely unrolled, so we could, if we want,
		//     hardcode the Zetas here instead of looking them up from memory.
		//     Is that worth it?

		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: 1 * 4}, zs[0]) // Zetas[1]

		ctButterfly(
			xs[0], xs[4], zs[0],
			xs[1], xs[5], zs[0],
			xs[2], xs[6], zs[0],
			xs[3], xs[7], zs[0],
		)

		// Second level
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: 2 * 4}, zs[0]) // Zetas[2]
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: 3 * 4}, zs[1]) // Zetas[3]

		ctButterfly(
			xs[0], xs[2], zs[0],
			xs[1], xs[3], zs[0],
			xs[4], xs[6], zs[1],
			xs[5], xs[7], zs[1],
		)

		// Third level
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: 4 * 4}, zs[0]) // Zetas[4]
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: 5 * 4}, zs[1]) // Zetas[5]
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: 6 * 4}, zs[2]) // Zetas[6]
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: 7 * 4}, zs[3]) // Zetas[7]

		ctButterfly(
			xs[0], xs[1], zs[0],
			xs[2], xs[3], zs[1],
			xs[4], xs[5], zs[2],
			xs[6], xs[7], zs[3],
		)

		for i := 0; i < 8; i++ {
			VMOVDQA(xs[i], Mem{Base: buf_ptr, Disp: 8 * (32*i + 4*offset)})
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
		// Load the first 32 coefficients from level 3.  Recall that buf_ptr
		// has 64 bits of space for each coefficient.
		for i := 0; i < 8; i++ {
			VMOVDQA(Mem{Base: buf_ptr, Disp: 8 * 4 * (8*offset + i)}, xs[i])
		}

		// Fourth level
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (8 + offset) * 4}, zs[0])
		ctButterfly(
			xs[0], xs[4], zs[0],
			xs[1], xs[5], zs[0],
			xs[2], xs[6], zs[0],
			xs[3], xs[7], zs[0],
		)

		// Fifth level
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (16 + offset*2) * 4}, zs[0])
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (16 + offset*2 + 1) * 4}, zs[1])
		ctButterfly(
			xs[0], xs[2], zs[0],
			xs[1], xs[3], zs[0],
			xs[4], xs[6], zs[1],
			xs[5], xs[7], zs[1],
		)

		// Sixth level
		for i := 0; i < 4; i++ {
			VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (32 + offset*4 + i) * 4}, zs[i])
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
			VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (64 + offset*8 + i*2) * 4}, tmp)
			VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (64 + offset*8 + i*2 + 1) * 4}, zs[i])
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
			VPMOVZXDQ(Mem{Base: zetas_ptr, Disp: (128 + 4*i + offset*16) * 4}, zs[i])
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
		// moved out into memeory.

		VPSLLQ(U8(32), xs[1], xs[1])
		VPSLLQ(U8(32), xs[3], xs[3])
		VPSLLQ(U8(32), xs[5], xs[5])
		VPSLLQ(U8(32), xs[7], xs[7])

		VPBLENDD(U8(170), xs[1], xs[0], xs[0])
		VPBLENDD(U8(170), xs[3], xs[2], xs[2])
		VPBLENDD(U8(170), xs[5], xs[4], xs[4])
		VPBLENDD(U8(170), xs[7], xs[6], xs[6])

		for i := 0; i < 4; i++ {
			VMOVDQU(xs[2*i], Mem{Base: p_ptr, Disp: 8 * 4 * (4*offset + i)})
		}
	}

	RET()
}

func invNttAVX2() {
	// Just like with the generic implementation, we do the operations of
	// NTT in reverse, except for two things: we hoist out all divisions by
	// two from the Gentleman-Sande butterflies and accumulate them to one
	// big division by 2^8 at the end.
	TEXT("invNttAVX2", 0, "func(p *[256]uint32)")
	Pragma("noescape")
	p_ptr := Load(Param("p"), GP64())
	zetas_ptr := GP64()
	LEAQ(NewDataAddr(Symbol{Name: "·InvZetas"}, 0), zetas_ptr)

	// We allocate a [256]uint64 on the stack aligned to 32 bytes to hold
	// "buf" which contains intermediate coefficients like "p" in the generic
	// algorithm, but then in uint64s instead of uint32s.
	buf_ptr := GP64()
	LEAQ(AllocLocal(256*8+32), buf_ptr) // +32 to be able to align
	and_imm64(0xffffffffffffffe0, buf_ptr)

	q := YMM()
	broadcast_imm32(params.Q, q)
	q256 := YMM()
	broadcast_imm32(256*params.Q, q256)
	qinv := YMM()
	broadcast_imm32(params.Qinv, qinv)

	// Computes 4x4 doubled Gentleman--Sande butterflies (a,b) |-> (a+b, ζ(a-b)).
	gsButterfly := func(a1, b1, zeta1, a2, b2, zeta2, a3, b3, zeta3,
		a4, b4, zeta4 Op) {
		t := [4]Op{YMM(), YMM(), YMM(), YMM()}
		a := [4]Op{a1, a2, a3, a4}
		b := [4]Op{b1, b2, b3, b4}
		zeta := [4]Op{zeta1, zeta2, zeta3, zeta4}

		// XXX be more parallel when we have more registers available, when
		//     we don't use the full four registers for zetas.
		for i := 0; i < 4; i++ {
			// Set t = 256Q + a in preparation of substracting b
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
			VMOVDQU(Mem{Base: p_ptr, Disp: 8 * 4 * (4*offset + i)}, xs[2*i])
		}

		// Move odd coeffs of xs[2*i] into xs[2*i+1] and shift down.  Ignoring
		// the odd coefficients, we have 0 2 4 6 in xs[0] and 1 3 4 5 in xs[1].
		for i := 0; i < 4; i++ {
			VPSRLQ(U8(32), xs[2*i], xs[2*i+1])
		}

		// Eighth level
		for i := 0; i < 4; i++ {
			VPMOVZXDQ(Mem{Base: zetas_ptr, Disp: 4 * 4 * (4*offset + i)}, zs[i])
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
			VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (128 + offset*8 + i*2) * 4}, tmp)
			VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (128 + offset*8 + i*2 + 1) * 4}, zs[i])
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
			VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (192 + offset*4 + i) * 4}, zs[i])
		}

		gsButterfly(
			xs[0], xs[1], zs[0],
			xs[2], xs[3], zs[1],
			xs[4], xs[5], zs[2],
			xs[6], xs[7], zs[3],
		)

		// Fifth level
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (224 + offset*2) * 4}, zs[0])
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (224 + offset*2 + 1) * 4}, zs[1])

		gsButterfly(
			xs[0], xs[2], zs[0],
			xs[1], xs[3], zs[0],
			xs[4], xs[6], zs[1],
			xs[5], xs[7], zs[1],
		)

		// Fourth level
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (240 + offset) * 4}, zs[0])

		gsButterfly(
			xs[0], xs[4], zs[0],
			xs[1], xs[5], zs[0],
			xs[2], xs[6], zs[0],
			xs[3], xs[7], zs[0],
		)

		for i := 0; i < 8; i++ {
			VMOVDQA(xs[i], Mem{Base: buf_ptr, Disp: 8 * 4 * (8*offset + i)})
		}
	}

	// XXX should we really unroll this loop?
	for offset := 0; offset < 8; offset++ {
		for i := 0; i < 8; i++ {
			VMOVDQA(Mem{Base: buf_ptr, Disp: 8 * (32*i + 4*offset)}, xs[i])
		}

		// Third level
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (248 * 4)}, zs[0])
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (249 * 4)}, zs[1])
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (250 * 4)}, zs[2])
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (251 * 4)}, zs[3])

		gsButterfly(
			xs[0], xs[1], zs[0],
			xs[2], xs[3], zs[1],
			xs[4], xs[5], zs[2],
			xs[6], xs[7], zs[3],
		)

		// Second level
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (252 * 4)}, zs[0])
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (253 * 4)}, zs[1])

		gsButterfly(
			xs[0], xs[2], zs[0],
			xs[1], xs[3], zs[0],
			xs[4], xs[6], zs[1],
			xs[5], xs[7], zs[1],
		)

		// First level
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (254 * 4)}, zs[0])

		gsButterfly(
			xs[0], xs[4], zs[0],
			xs[1], xs[5], zs[0],
			xs[2], xs[6], zs[0],
			xs[3], xs[7], zs[0],
		)

		// Finally, we multiply by 41978 = (256)^-1 R^2 ...
		rOver256 := YMM()
		broadcast_imm32(params.ROver256, rOver256)

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
			VMOVDQA(xs[i], Mem{Base: buf_ptr, Disp: 8 * (32*i + 4*offset)})
		}
	}

	// Finally, we copy the 32b results from the [256]uint64 buf to
	// the [256]uint32 p.
	// XXX is this the most efficient way?
	for j := 0; j < 8; j++ {
		for i := 0; i < 8; i++ {
			VMOVDQA(Mem{Base: buf_ptr, Disp: 32 * (8*j + i)}, xs[i])
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
			VMOVDQU(xs[2*i], Mem{Base: p_ptr, Disp: 32 * (4*j + i)})
		}
	}

	RET()
}

// XXX Split out into separate file.  To do this we need to figure out how
//     to share code properly between avo modules.
func mulHatAVX2() {
	TEXT("mulHatAVX2", 0, "func(p, a, b *[256]uint32)")
	Pragma("noescape")
	p_ptr := Load(Param("p"), GP64())
	a_ptr := Load(Param("a"), GP64())
	b_ptr := Load(Param("b"), GP64())

	q := YMM()
	broadcast_imm32(params.Q, q)
	qinv := YMM()
	broadcast_imm32(params.Qinv, qinv)

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
			VPMOVZXDQ(Mem{Base: a_ptr, Disp: 16 * (4*j + i)}, a[i])
		}
		for i := 0; i < 4; i++ {
			VPMOVZXDQ(Mem{Base: b_ptr, Disp: 16 * (4*j + i)}, b[i])
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
			VMOVDQU(b[2*i], Mem{Base: p_ptr, Disp: 32 * (2*j + i)})
		}
	}

	RET()
}

func addAVX2() {
	TEXT("addAVX2", 0, "func(p, a, b *[256]uint32)")
	Pragma("noescape")
	p_ptr := Load(Param("p"), GP64())
	a_ptr := Load(Param("a"), GP64())
	b_ptr := Load(Param("b"), GP64())

	var a [8]VecVirtual
	var b [8]VecVirtual
	for i := 0; i < 8; i++ {
		a[i] = YMM()
		b[i] = YMM()
	}

	// XXX is unrolling worth it?
	for j := 0; j < 4; j++ {
		for i := 0; i < 8; i++ {
			VMOVDQU(Mem{Base: a_ptr, Disp: 32 * (8*j + i)}, a[i])
		}
		for i := 0; i < 8; i++ {
			VMOVDQU(Mem{Base: b_ptr, Disp: 32 * (8*j + i)}, b[i])
		}
		for i := 0; i < 8; i++ {
			VPADDQ(a[i], b[i], b[i])
		}
		for i := 0; i < 8; i++ {
			VMOVDQU(b[i], Mem{Base: p_ptr, Disp: 32 * (8*j + i)})
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

	Generate()
}
