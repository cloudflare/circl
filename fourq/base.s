#include "base.h"

// func bfeHalf(c, a *baseFieldElem)
TEXT ·bfeHalf(SB),0,$0-16
	MOVQ a+8(FP), DI
	bfeMov(0(DI),8(DI), AX,BX)

	SHLQ $1, BX
	SHRQ $1, BX:AX
	SHRQ $1, AX:BX
	SHRQ $1, BX

	MOVQ c+0(FP), DI
	bfeMov(AX,BX, 0(DI),8(DI))
	RET

// func bfeDbl(c, a *baseFieldElem)
TEXT ·bfeDbl(SB),0,$0-16
	MOVQ a+8(FP), DI
	bfeMov(0(DI),8(DI), AX,BX)
	bfeDbl(AX,BX)

	MOVQ c+0(FP), DI
	bfeMov(AX,BX, 0(DI),8(DI))
	RET

// func bfeAdd(c, a, b *baseFieldElem)
TEXT ·bfeAdd(SB),0,$0-24
	MOVQ a+8(FP), DI
	MOVQ b+16(FP), SI
	bfeMov(0(DI),8(DI), AX,BX)
	bfeAdd(0(SI),8(SI), AX,BX)

	MOVQ c+0(FP), DI
	bfeMov(AX,BX, 0(DI),8(DI))
	RET

// func bfeSub(c, a, b *baseFieldElem)
TEXT ·bfeSub(SB),0,$0-24
	MOVQ a+8(FP), DI
	MOVQ b+16(FP), SI
	bfeMov(0(SI),8(SI), AX,BX)
	bfeSub(0(DI),8(DI), AX,BX)

	MOVQ c+0(FP), DI
	bfeMov(AX,BX, 0(DI),8(DI))
	RET

// func bfeMul(c, a, b *baseFieldElem)
TEXT ·bfeMul(SB),0,$0-24
	MOVQ a+8(FP), DI
	MOVQ b+16(FP), SI
	MOVQ $0, CX

	MOVQ 0(DI), AX
	MULQ 0(SI)
	MOVQ AX, R8
	MOVQ DX, R9

	MOVQ 0(DI), AX
	MULQ 8(SI)
	SHLQ $1, DX
	ADDQ DX, R8
	ADCQ AX, R9
	ADCQ $0, CX

	MOVQ 8(DI), AX
	MULQ 0(SI)
	SHLQ $1, DX
	ADDQ DX, R8
	ADCQ AX, R9
	ADCQ $0, CX

	MOVQ 8(DI), AX
	MULQ 8(SI)
	SHLQ $1, DX
	SHLQ $1, AX
	ADCQ $0, DX
	ADDQ AX, R8
	ADCQ DX, R9
	ADCQ $0, CX

	SHLQ $1, CX
	BTRQ $63, R9
	ADCQ CX, R8
	ADCQ $0, R9
	bfeReduce(R8,R9)

	// bfeMul(CX, 0(DI),8(DI), 0(SI),8(SI), R8,R9)
	// bfeMulReduce(CX, R8,R9)

	MOVQ c+0(FP), DI
	bfeMov(R8,R9, 0(DI),8(DI))
	RET

// func bfeSquare(c, a *baseFieldElem)
TEXT ·bfeSquare(SB),0,$0-16
	MOVQ a+8(FP), DI
	MOVQ $0, CX

	MOVQ 0(DI), AX
	MULQ 0(DI)
	MOVQ AX, R8
	MOVQ DX, R9

	MOVQ 0(DI), AX
	MULQ 8(DI)
	SHLQ $1, DX
	ADDQ DX, R8
	ADCQ AX, R9
	ADCQ $0, CX
	ADDQ DX, R8
	ADCQ AX, R9
	ADCQ $0, CX

	MOVQ 8(DI), AX
	MULQ 8(DI)
	SHLQ $1, DX
	SHLQ $1, AX
	ADCQ $0, DX
	ADDQ AX, R8
	ADCQ DX, R9
	ADCQ $0, CX

	SHLQ $1, CX
	BTRQ $63, R9
	ADCQ CX, R8
	ADCQ $0, R9
	bfeReduce(R8,R9)

	MOVQ c+0(FP), DI
	bfeMov(R8,R9, 0(DI),8(DI))
	RET
