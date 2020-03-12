// +build amd64,!purego

#include "textflag.h"
#include "fp_amd64.h"

// fpModp sets e to zero if it is equal to p. This is the only case where c
// will not naturally be reduced to canonical form.
// func fpMod(c *fp)
TEXT ·fpMod(SB),0,$0-8
    MOVQ c+0(FP), DI
    _fpMod(0(DI))
    RET

// func fpAdd(c, a, b *fp)
TEXT ·fpAdd(SB),0,$0-24
    MOVQ c+0(FP), DI
    MOVQ a+8(FP), SI
    MOVQ b+16(FP), BX
    _fpAdd(0(DI), 0(SI), 0(BX))
    RET

// func fpSub(c, a, b *fp)
TEXT ·fpSub(SB),0,$0-24
    MOVQ c+0(FP), DI
    MOVQ a+8(FP), SI
    MOVQ b+16(FP), BX
    _fpSub(0(DI), 0(SI), 0(BX))
    RET

// func fpHlf(c, a *fp)
TEXT ·fpHlf(SB),0,$0-16
	MOVQ a+8(FP), DI
    MOVQ 0(DI), AX
    MOVQ 8(DI), BX

	SHLQ $1, BX
	SHRQ $1, AX, BX
	SHRQ $1, BX, AX
	SHRQ $1, BX

	MOVQ c+0(FP), DI
    MOVQ AX, 0(DI)
    MOVQ BX, 8(DI)
	RET

// func fpMul(c, a, b *fp)
TEXT ·fpMul(SB),0,$0-24
    MOVQ a+8(FP), DI
    MOVQ b+16(FP), SI
    _fpMulLeg(R10, R9, R8, 0(DI), 0(SI))
    SHLQ $1, R10
    BTRQ $63, R9
    ADCQ R10, R8
    ADCQ  $0, R9
    _fpReduce(R8, R9)

    MOVQ c+0(FP), DI
    MOVQ R8, 0(DI)
    MOVQ R9, 8(DI)
    RET

// func fpSqr(c, a *fp)
TEXT ·fpSqr(SB),0,$0-16
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
    _fpReduce(R8, R9)

    MOVQ c+0(FP), DI
    MOVQ R8, 0(DI)
    MOVQ R9, 8(DI)
    RET
