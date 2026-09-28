// AVO program generating the vectorized masked GF(2) row additions used by the
// Classic McEliece key generator. It emits an AVX-512 kernel (64-byte blocks)
// and an AVX2 kernel (32-byte blocks); the Go dispatcher selects the widest
// path the CPU supports and falls back to a pure-Go implementation otherwise.
//
//go:generate go run src.go -out ../../amd64.s -stubs ../../stubs_amd64.go -pkg matops

package main

import (
	. "github.com/mmcloughlin/avo/build"   // nolint:golint,stylecheck
	. "github.com/mmcloughlin/avo/operand" // nolint:golint,stylecheck
)

func main() {
	ConstraintExpr("amd64,!purego")

	avx512()
	avx2()

	Generate()
}

func avx512() {
	TEXT("addMaskedAVX512", NOSPLIT, "func(dst, src *byte, n int, mask byte)")
	Doc("addMaskedAVX512 sets dst[i] ^= src[i] & mask for i in [0,n), with n a " +
		"multiple of 64, using AVX-512. The work performed is independent of " +
		"mask and of the buffer contents.")

	dst := Load(Param("dst"), GP64())
	src := Load(Param("src"), GP64())
	n := Load(Param("n"), GP64())

	// Broadcast the mask byte across all 64 lanes of a ZMM register.
	maskb := Load(Param("mask"), GP8())
	mask32 := GP32()
	MOVBLZX(maskb, mask32)
	maskz := ZMM()
	VPBROADCASTB(mask32, maskz)

	Label("loop")
	CMPQ(n, Imm(0))
	JE(LabelRef("done"))

	s := ZMM()
	VMOVDQU8(Mem{Base: src}, s)
	VPANDQ(maskz, s, s)
	d := ZMM()
	VMOVDQU8(Mem{Base: dst}, d)
	VPXORQ(s, d, d)
	VMOVDQU8(d, Mem{Base: dst})

	ADDQ(Imm(64), src)
	ADDQ(Imm(64), dst)
	SUBQ(Imm(64), n)
	JMP(LabelRef("loop"))

	Label("done")
	VZEROUPPER()
	RET()
}

func avx2() {
	TEXT("addMaskedAVX2", NOSPLIT, "func(dst, src *byte, n int, mask byte)")
	Doc("addMaskedAVX2 sets dst[i] ^= src[i] & mask for i in [0,n), with n a " +
		"multiple of 32, using AVX2. The work performed is independent of mask " +
		"and of the buffer contents.")

	dst := Load(Param("dst"), GP64())
	src := Load(Param("src"), GP64())
	n := Load(Param("n"), GP64())

	// Broadcast the mask byte across all 32 lanes of a YMM register.
	maskb := Load(Param("mask"), GP8())
	mask32 := GP32()
	MOVBLZX(maskb, mask32)
	maskx := XMM()
	VMOVD(mask32, maskx)
	masky := YMM()
	VPBROADCASTB(maskx, masky)

	Label("loop")
	CMPQ(n, Imm(0))
	JE(LabelRef("done"))

	s := YMM()
	VMOVDQU(Mem{Base: src}, s)
	VPAND(masky, s, s)
	d := YMM()
	VMOVDQU(Mem{Base: dst}, d)
	VPXOR(s, d, d)
	VMOVDQU(d, Mem{Base: dst})

	ADDQ(Imm(32), src)
	ADDQ(Imm(32), dst)
	SUBQ(Imm(32), n)
	JMP(LabelRef("loop"))

	Label("done")
	VZEROUPPER()
	RET()
}
