//go:build arm64 && !purego

#include "go_asm.h"
#include "textflag.h"

// to get raw encoding: e.g. echo "sshr    v4.4s, v0.4s, #31" | llvm-mc -triple=arm64 -show-encoding

// func polyAddARM64(p, a, b *Poly)
TEXT ·polyAddARM64(SB), NOSPLIT|NOFRAME, $0-24
    MOVD    p+0(FP), R0
    MOVD    a+8(FP), R1
    MOVD    b+16(FP), R2

    MOVW    $(const_N / 16), R3 // loop iterations (for each iteration we emit 16 elements)

loop:
    VLD1.P  (64)(R1), [V0.S4, V1.S4, V2.S4, V3.S4]
    VLD1.P  (64)(R2), [V4.S4, V5.S4, V6.S4, V7.S4]

    VADD    V4.S4, V0.S4, V0.S4
    VADD    V5.S4, V1.S4, V1.S4
    VADD    V6.S4, V2.S4, V2.S4
    VADD    V7.S4, V3.S4, V3.S4

    VST1.P  [V0.S4, V1.S4, V2.S4, V3.S4], (64)(R0)

    SUBS    $1, R3, R3
    BGT     loop

    RET


// func polyPackLe16ARM64(p *Poly, buf *byte)
TEXT ·polyPackLe16ARM64(SB), NOSPLIT|NOFRAME, $0-16
    MOVD    p+0(FP), R0
    MOVD    buf+8(FP), R1

    MOVW    $(const_PolyLe16Size / 16), R3 // loop iterations (for each iteration we emit 16 elements)
    VMOVQ   $0x1c0c180814041000, $0x3c2c382834243020, V15 // value explained at VTBL call

    // on the first iteration we have:
    // V0 = (p[0], p[4], p[8], p[12])       V1 = (p[1], p[5], p[9], p[13])
    // V2 = (p[2], p[6], p[10], p[14])      V3 = (p[3], p[7], p[11], p[15])
    // V4 = (p[16], p[20], p[24], p[28])    V5 = (p[17], p[21], p[25], p[29])
    // V6 = (p[18], p[22], p[26], p[30])    V7 = (p[19], p[23], p[27], p[31])
loop:
    VLD4.P  (64)(R0), [V0.S4, V1.S4, V2.S4, V3.S4]
    VLD4.P  (64)(R0), [V4.S4, V5.S4, V6.S4, V7.S4]

    VSHL    $4, V1.S4, V1.S4
    VSHL    $4, V3.S4, V3.S4
    VSHL    $4, V5.S4, V5.S4
    VSHL    $4, V7.S4, V7.S4

    // tmp = p[even] | (p[odd] << 4)
    VORR    V1.B16, V0.B16, V10.B16
    VORR    V3.B16, V2.B16, V11.B16
    VORR    V5.B16, V4.B16, V12.B16
    VORR    V7.B16, V6.B16, V13.B16

    // so now we need to pick elements based on order:
    // first from V10; first from V11; second from V10; second from V11;
    // ...
    // first from V12; first from V13; second from V12; second from V13;
    // V15 contains the indices which correspond to the pick order above
    VTBL    V15.B16, [V10.B16, V11.B16, V12.B16, V13.B16], V16.B16

    VST1.P  [V16.B16], (16)(R1)

    SUBS    $1, R3, R3
    BGT     loop

    RET

// func polyMulBy2toDARM64(p, q *Poly)
TEXT ·polyMulBy2toDARM64(SB), NOSPLIT|NOFRAME, $0-16
    MOVD    p+0(FP), R0
    MOVD    q+8(FP), R1

    MOVW    $(const_N / 16), R2

loop:
    VLD1.P  (64)(R1), [V0.S4, V1.S4, V2.S4, V3.S4]

    VSHL    $(const_D), V0.S4, V0.S4
    VSHL    $(const_D), V1.S4, V1.S4
    VSHL    $(const_D), V2.S4, V2.S4
    VSHL    $(const_D), V3.S4, V3.S4

    VST1.P  [V0.S4, V1.S4, V2.S4, V3.S4], (64)(R0)

    SUBS    $1, R2, R2
    BGT     loop

    RET

// func polySubARM64(p, a, b *Poly)
TEXT ·polySubARM64(SB), NOSPLIT|NOFRAME, $0-24
    MOVD    p+0(FP), R0
    MOVD    a+8(FP), R1
    MOVD    b+16(FP), R2

    MOVW    $(const_N / 16), R3
    MOVW    $(const_Q << 1), R4

    VDUP    R4, V8.S4

    // p = a + (2q - b)
loop:
    VLD1.P  (64)(R1), [V0.S4, V1.S4, V2.S4, V3.S4]
    VLD1.P  (64)(R2), [V4.S4, V5.S4, V6.S4, V7.S4]

    VSUB    V4.S4, V8.S4, V4.S4
    VSUB    V5.S4, V8.S4, V5.S4
    VSUB    V6.S4, V8.S4, V6.S4
    VSUB    V7.S4, V8.S4, V7.S4

    VADD    V4.S4, V0.S4, V0.S4
    VADD    V5.S4, V1.S4, V1.S4
    VADD    V6.S4, V2.S4, V2.S4
    VADD    V7.S4, V3.S4, V3.S4

    VST1.P  [V0.S4, V1.S4, V2.S4, V3.S4], (64)(R0)

    SUBS    $1, R3, R3
    BGT     loop

    RET

// func polyExceedsARM64(p *Poly, bound uint32) bool
TEXT ·polyExceedsARM64(SB), NOSPLIT|NOFRAME, $0-24
    MOVD    p+0(FP), R0
    MOVW    bound+8(FP), R1

    MOVW    $(const_N / 16), R3
    MOVW    $((const_Q - 1) / 2), R4

    VDUP    R4, V8.S4
    VDUP    R1, V9.S4

loop:
    VLD1.P  (64)(R0), [V0.S4, V1.S4, V2.S4, V3.S4]

    VSUB    V0.S4, V8.S4, V0.S4
    VSUB    V1.S4, V8.S4, V1.S4
    VSUB    V2.S4, V8.S4, V2.S4
    VSUB    V3.S4, V8.S4, V3.S4

    WORD    $0x4f210404 //  sshr    v4.4s, v0.4s, #31
    WORD    $0x4f210425 //  sshr    v5.4s, v1.4s, #31
    WORD    $0x4f210446 //  sshr    v6.4s, v2.4s, #31
    WORD    $0x4f210467 //  sshr    v7.4s, v3.4s, #31

    VEOR    V4.B16, V0.B16, V0.B16
    VEOR    V5.B16, V1.B16, V1.B16
    VEOR    V6.B16, V2.B16, V2.B16
    VEOR    V7.B16, V3.B16, V3.B16

    VSUB    V0.S4, V8.S4, V0.S4
    VSUB    V1.S4, V8.S4, V1.S4
    VSUB    V2.S4, V8.S4, V2.S4
    VSUB    V3.S4, V8.S4, V3.S4

    WORD    $0x6ea93c00 //  cmhs    v0.4s, v0.4s, v9.4s
    WORD    $0x6ea93c21 //  cmhs    v1.4s, v1.4s, v9.4s
    WORD    $0x6ea93c42 //  cmhs    v2.4s, v2.4s, v9.4s
    WORD    $0x6ea93c63 //  cmhs    v3.4s, v3.4s, v9.4s

    WORD    $0x6eb0a800 //  umaxv   s0, v0.4s
    WORD    $0x6eb0a821 //  umaxv   s1, v1.4s
    WORD    $0x6eb0a842 //  umaxv   s2, v2.4s
    WORD    $0x6eb0a863 //  umaxv   s3, v3.4s

    VMOV    V0.S[0], R5
    VMOV    V1.S[0], R6
    VMOV    V2.S[0], R7
    VMOV    V3.S[0], R8

    ORR     R6, R5, R9
    ORR     R8, R7, R10
    ORR     R9, R10, R10

    CBNZ     R10, exceeded

    SUBS    $1, R3, R3
    BGT     loop

    MOVB    ZR, ret+16(FP) // no value inside p exceeded the bound

    RET

exceeded:
    MOVW    $1, R5
    MOVB    R5, ret+16(FP) // at least one value inside the batch (16 elements) exceeded the bound

    RET
