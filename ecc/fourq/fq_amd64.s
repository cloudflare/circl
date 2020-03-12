// +build amd64,!purego

#include "fq_amd64.h"

#define fqMulLegacy \
    _fqMulLeg(0(DI),0(SI),0(BX))
#define fqMulBmi2 \
    _fqMulBmi2(0(DI),0(SI),0(BX))

#define fqSqrLegacy \
    _fqSqrLeg(0(DI),0(SI))
#define fqSqrBmi2 \
    _fqSqrBmi2(0(DI),0(SI))

// func fqCmov(c, a *fq, b int)
TEXT ·fqCmov(SB),0,$0-24
    MOVQ c+0(FP), DI
    MOVQ a+8(FP), SI
    MOVQ b+16(FP), BX
    TESTQ BX, BX
    MOVQ  0(DI), AX; MOVQ  0(SI), DX; CMOVQNE DX, AX; MOVQ AX,  0(DI);
    MOVQ  8(DI), AX; MOVQ  8(SI), DX; CMOVQNE DX, AX; MOVQ AX,  8(DI);
    MOVQ 16(DI), AX; MOVQ 16(SI), DX; CMOVQNE DX, AX; MOVQ AX, 16(DI);
    MOVQ 24(DI), AX; MOVQ 24(SI), DX; CMOVQNE DX, AX; MOVQ AX, 24(DI);
    RET

// func fqAdd(c, a, b *fq)
TEXT ·fqAdd(SB),0,$0-24
    MOVQ c+0(FP), DI
    MOVQ a+8(FP), SI
    MOVQ b+16(FP), BX
    _fqAdd(0(DI), 0(SI), 0(BX))
    RET

// func fqSub(c, a, b *fq)
TEXT ·fqSub(SB),0,$0-24
    MOVQ c+0(FP), DI
    MOVQ a+8(FP), SI
    MOVQ b+16(FP), BX
    _fqSub(0(DI), 0(SI), 0(BX))
    RET

// func fqMul(c, a, b *fq)
TEXT ·fqMul(SB),0,$0-24
    MOVQ c+0(FP), DI
    MOVQ a+8(FP), SI
    MOVQ b+16(FP), BX
    CHECK_BMI2(LFQMUL, fqMulLegacy, fqMulBmi2)
    RET

// func fqSqr(c, a *fq)
TEXT ·fqSqr(SB),0,$0-16
    MOVQ c+0(FP), DI
    MOVQ a+8(FP), SI
    CHECK_BMI2(LFQSQR, fqSqrLegacy, fqSqrBmi2)
    RET
