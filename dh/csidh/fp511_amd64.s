// +build amd64

#include "textflag.h"

// Multiplies 512-bit value by 64-bit value. Uses MULQ instruction to
// multiply 2 64-bit values.
//
// Result: x = (y * z) mod 2^512
//
// Registers used: AX, CX, DX, SI, DI, R8
//
// func mul512Amd64(a, b *Fp, c uint64)
TEXT ·mul512Amd64(SB), NOSPLIT, $0-24
    MOVQ    a+0(FP), DI    // result
    MOVQ    b+8(FP), SI    // multiplicand

    // Check whether to use optimized implementation
    CMPB    ·hasBMI2(SB), $1
    JE      mul512_mulx

    MOVQ c+16(FP), R10  // 64 bit multiplier, used by MULQ
    MOVQ R10, AX; MULQ  0(SI);                            MOVQ DX, R11; MOVQ AX,  0(DI) //x[0]
    MOVQ R10, AX; MULQ  8(SI); ADDQ R11, AX; ADCQ $0, DX; MOVQ DX, R11; MOVQ AX,  8(DI) //x[1]
    MOVQ R10, AX; MULQ 16(SI); ADDQ R11, AX; ADCQ $0, DX; MOVQ DX, R11; MOVQ AX, 16(DI) //x[2]
    MOVQ R10, AX; MULQ 24(SI); ADDQ R11, AX; ADCQ $0, DX; MOVQ DX, R11; MOVQ AX, 24(DI) //x[3]
    MOVQ R10, AX; MULQ 32(SI); ADDQ R11, AX; ADCQ $0, DX; MOVQ DX, R11; MOVQ AX, 32(DI) //x[4]
    MOVQ R10, AX; MULQ 40(SI); ADDQ R11, AX; ADCQ $0, DX; MOVQ DX, R11; MOVQ AX, 40(DI) //x[5]
    MOVQ R10, AX; MULQ 48(SI); ADDQ R11, AX; ADCQ $0, DX; MOVQ DX, R11; MOVQ AX, 48(DI) //x[6]
    MOVQ R10, AX; MULQ 56(SI); ADDQ R11, AX;                            MOVQ AX, 56(DI) //x[7]
    RET

// Optimized for CPUs with BMI2
mul512_mulx:
    MOVQ     c+16(FP), DX                                  // 64 bit multiplier, used by MULX
    MULXQ    0(SI), AX, R10; MOVQ AX, 0(DI)                // x[0]
    MULXQ    8(SI), AX, R11; ADDQ R10, AX; MOVQ AX,  8(DI) // x[1]
    MULXQ   16(SI), AX, R10; ADCQ R11, AX; MOVQ AX, 16(DI) // x[2]
    MULXQ   24(SI), AX, R11; ADCQ R10, AX; MOVQ AX, 24(DI) // x[3]
    MULXQ   32(SI), AX, R10; ADCQ R11, AX; MOVQ AX, 32(DI) // x[4]
    MULXQ   40(SI), AX, R11; ADCQ R10, AX; MOVQ AX, 40(DI) // x[5]
    MULXQ   48(SI), AX, R10; ADCQ R11, AX; MOVQ AX, 48(DI) // x[6]
    MULXQ   56(SI), AX, R11; ADCQ R10, AX; MOVQ AX, 56(DI) // x[7]
    RET

TEXT ·cswap512Amd64(SB),NOSPLIT,$0-17
    MOVQ    x+0(FP), DI
    MOVQ    y+8(FP), SI
    MOVBLZX choice+16(FP), AX       // AL = 0 or 1

    // Make AX, so that either all bits are set or non
    // AX = 0 or 1
    NEGQ    AX

    // Fill xmm15. After this step first half of XMM15 is
    // just zeros and second half is whatever in AX
    MOVQ    AX, X15

    // Copy lower double word everywhere else. So that
    // XMM15=AL|AL|AL|AL. As AX has either all bits set
    // or non result will be that XMM15 has also either
    // all bits set or non of them.
    PSHUFD $0, X15, X15

#ifndef CSWAP_BLOCK
#define CSWAP_BLOCK(idx)       \
    MOVOU   (idx*16)(DI), X0 \
    MOVOU   (idx*16)(SI), X1 \
    \ // X2 = mask & (X0 ^ X1)
    MOVO     X1, X2 \
    PXOR     X0, X2 \
    PAND    X15, X2 \
    \
    PXOR     X2, X0 \
    PXOR     X2, X1 \
    \
    MOVOU    X0, (idx*16)(DI) \
    MOVOU    X1, (idx*16)(SI)
#endif

    CSWAP_BLOCK(0)
    CSWAP_BLOCK(1)
    CSWAP_BLOCK(2)
    CSWAP_BLOCK(3)

    RET

// mulAsm implements montgomery multiplication interleaved with
// montgomery reduction. It uses MULX and ADCX/ADOX instructions.
// Implementation specific to 511-bit prime 'p'
//
// func mulBmiAsm(res, x, y *fp)
TEXT ·mulBmiAsm(SB),NOSPLIT,$8-24

    MOVQ x+8(FP), DI // multiplicand
    MOVQ y+16(FP), SI // multiplier

    XORQ  R8,  R8
    XORQ  R9,  R9
    XORQ R10, R10
    XORQ R11, R11
    XORQ R12, R12
    XORQ R13, R13
    XORQ R14, R14
    XORQ  CX,  CX

    MOVQ BP, 0(SP) // push: BP is Callee-save.
    XORQ BP, BP

// Uses BMI2 (MULX)
#ifdef MULS_MULX_512
#undef MULS_MULX_512
#endif
#define MULS_MULX_512(idx, r0, r1, r2, r3, r4, r5, r6, r7, r8) \
    \ // Reduction step
    MOVQ  ( 0)(SI), DX      \
    MULXQ ( 8*idx)(DI), DX, AX  \
    ADDQ  r0, DX            \
    MOVQ ·pNegInv(SB), AX \
    MULXQ AX, DX, AX  \
    \
    XORQ  AX, AX; \
    MOVQ ·p+ 0(SB), AX; MULXQ AX, AX, BX;  ADOXQ AX, r0; ADCXQ BX, r1 \
    MOVQ ·p+ 8(SB), AX; MULXQ AX, AX, BX;  ADOXQ AX, r1; ADCXQ BX, r2 \
    MOVQ ·p+16(SB), AX; MULXQ AX, AX, BX;  ADOXQ AX, r2; ADCXQ BX, r3 \
    MOVQ ·p+24(SB), AX; MULXQ AX, AX, BX;  ADOXQ AX, r3; ADCXQ BX, r4 \
    MOVQ ·p+32(SB), AX; MULXQ AX, AX, BX;  ADOXQ AX, r4; ADCXQ BX, r5 \
    MOVQ ·p+40(SB), AX; MULXQ AX, AX, BX;  ADOXQ AX, r5; ADCXQ BX, r6 \
    MOVQ ·p+48(SB), AX; MULXQ AX, AX, BX;  ADOXQ AX, r6; ADCXQ BX, r7 \
    MOVQ ·p+56(SB), AX; MULXQ AX, AX, BX;  ADOXQ AX, r7; ADCXQ BX, r8 \
    MOVQ  $0, AX; ;;;;;;;;;;;;;;;;;;;;;;;  ADOXQ AX, r8; \
    \ // Multiplication step
    MOVQ (8*idx)(DI), DX \
    \
    XORQ  AX, AX \
    MULXQ ( 0)(SI), AX, BX; ADOXQ AX, r0; ADCXQ BX, r1 \
    MULXQ ( 8)(SI), AX, BX; ADOXQ AX, r1; ADCXQ BX, r2 \
    MULXQ (16)(SI), AX, BX; ADOXQ AX, r2; ADCXQ BX, r3 \
    MULXQ (24)(SI), AX, BX; ADOXQ AX, r3; ADCXQ BX, r4 \
    MULXQ (32)(SI), AX, BX; ADOXQ AX, r4; ADCXQ BX, r5 \
    MULXQ (40)(SI), AX, BX; ADOXQ AX, r5; ADCXQ BX, r6 \
    MULXQ (48)(SI), AX, BX; ADOXQ AX, r6; ADCXQ BX, r7 \
    MULXQ (56)(SI), AX, BX; ADOXQ AX, r7; ADCXQ BX, r8 \
    MOVQ  $0, AX          ; ADOXQ AX, r8;

    MULS_MULX_512(0,  R8,  R9, R10, R11, R12, R13, R14,  CX,  BP)
    MULS_MULX_512(1,  R9, R10, R11, R12, R13, R14,  CX,  BP,  R8)
    MULS_MULX_512(2, R10, R11, R12, R13, R14,  CX,  BP,  R8,  R9)
    MULS_MULX_512(3, R11, R12, R13, R14,  CX,  BP,  R8,  R9, R10)
    MULS_MULX_512(4, R12, R13, R14,  CX,  BP,  R8,  R9, R10, R11)
    MULS_MULX_512(5, R13, R14,  CX,  BP,  R8,  R9, R10, R11, R12)
    MULS_MULX_512(6, R14,  CX,  BP,  R8,  R9, R10, R11, R12, R13)
    MULS_MULX_512(7,  CX,  BP,  R8,  R9, R10, R11, R12, R13, R14)
#undef MULS_MULX_512

    MOVQ res+0(FP), DI
    MOVQ  BP, ( 0)(DI)
    MOVQ  R8, ( 8)(DI)
    MOVQ  R9, (16)(DI)
    MOVQ R10, (24)(DI)
    MOVQ R11, (32)(DI)
    MOVQ R12, (40)(DI)
    MOVQ R13, (48)(DI)
    MOVQ R14, (56)(DI)
    MOVQ 0(SP), BP // pop: BP is Callee-save.

    // NOW DI needs to be reduced if > p
    RET
