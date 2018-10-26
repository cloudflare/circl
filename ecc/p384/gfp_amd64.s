// +build amd64

#include "textflag.h"

#include "gfp.h"
#include "mul.h"
#include "mul_bmi2.h"

TEXT ·gfpNeg(SB), NOSPLIT, $0-16
	MOVQ ·p+0(SB), R8
	MOVQ ·p+8(SB), R9
	MOVQ ·p+16(SB), R10
	MOVQ ·p+24(SB), R11
	MOVQ ·p+32(SB), R12
	MOVQ ·p+40(SB), R13

	MOVQ a+8(FP), DI
	SUBQ 0(DI), R8
	SBBQ 8(DI), R9
	SBBQ 16(DI), R10
	SBBQ 24(DI), R11
	SBBQ 32(DI), R12
	SBBQ 40(DI), R13

	MOVQ $0, R14
	gfpCarry(R8,R9,R10,R11,R12,R13,R14, R15,AX,BX,CX,DX,DI,SI)

	MOVQ c+0(FP), DI
	storeBlock(R8,R9,R10,R11,R12,R13, 0(DI))
	RET

TEXT ·gfpAdd(SB), NOSPLIT, $0-24
	MOVQ a+8(FP), DI
	MOVQ b+16(FP), SI

	loadBlock(0(DI), R8,R9,R10,R11,R12,R13)
	MOVQ $0, R14

	ADDQ  0(SI), R8
	ADCQ  8(SI), R9
	ADCQ 16(SI), R10
	ADCQ 24(SI), R11
	ADCQ 32(SI), R12
	ADCQ 40(SI), R13
	ADCQ $0, R14

	gfpCarry(R8,R9,R10,R11,R12,R13,R14, R15,AX,BX,CX,DX,DI,SI)

	MOVQ c+0(FP), DI
	storeBlock(R8,R9,R10,R11,R12,R13, 0(DI))
	RET

TEXT ·gfpSub(SB), NOSPLIT, $0-24
	MOVQ ·p+0(SB), R8
	MOVQ ·p+8(SB), R9
	MOVQ ·p+16(SB), R10
	MOVQ ·p+24(SB), R11
	MOVQ ·p+32(SB), R12
	MOVQ ·p+40(SB), R13

	MOVQ b+16(FP), DI
	SUBQ 0(DI), R8
	SBBQ 8(DI), R9
	SBBQ 16(DI), R10
	SBBQ 24(DI), R11
	SBBQ 32(DI), R12
	SBBQ 40(DI), R13

	MOVQ $0, R14
	MOVQ a+8(FP), DI
	ADDQ 0(DI), R8
	ADCQ 8(DI), R9
	ADCQ 16(DI), R10
	ADCQ 24(DI), R11
	ADCQ 32(DI), R12
	ADCQ 40(DI), R13
	ADCQ $0, R14

	gfpCarry(R8,R9,R10,R11,R12,R13,R14, R15,AX,BX,CX,DX,DI,SI)

	MOVQ c+0(FP), DI
	storeBlock(R8,R9,R10,R11,R12,R13, 0(DI))
	RET

TEXT ·gfpMul(SB), NOSPLIT, $240-24
	MOVQ a+8(FP), DI
	MOVQ b+16(FP), SI

	// Jump to a slightly different implementation if MULX isn't supported.
	CMPB ·hasBMI2(SB), $0
	JE   nobmi2Mul

	// T = a * b
	mulBMI2(0(DI),8(DI),16(DI),24(DI),32(DI),40(DI), 0(SI), 0(SP))
	storeBlock(R14,R15,R8,R9,R10,R11, 48(SP))

	// Reduce T.
	gfpReduceBMI2(0(SP))

	MOVQ c+0(FP), DI
	storeBlock(R14,R15,R8,R9,R10,R11, 0(DI))
	JMP end

nobmi2Mul:
	// T = a * b
	mul(0(DI),8(DI),16(DI),24(DI),32(DI),40(DI), 0(SI), 0(SP))

	// Reduce T.
	gfpReduce(0(SP))

	MOVQ c+0(FP), DI
	storeBlock(R14,R15,AX,BX,CX,DX, 0(DI))

end:
	RET
