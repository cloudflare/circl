//go:build arm64 && !purego

#include "textflag.h"

// func polyNTT(p *Poly, zetas *[N]uint32)
TEXT ·polyNTT(SB), NOSPLIT|NOFRAME, $0-16
    MOVD    p+0(FP), R0
    MOVD    zetas+8(FP), R1

    MOVW    $128, R2 // l
    MOVW    $256, R3 // N
    MOVZW   $0xE001, R20 // Q
    MOVKW   $(0x7F<<16), R20
    MOVZW   $0xDFFF, R21 // Qinv
    MOVKW   $(0xFC7F<<16), R21

    LSL     $1, R20, R22 // Q << 1

ntt_1:
    SUB     R2, R3, R4 // end
    LSL     $1, R2, R5 // step
    MOVW    $0, R6 // offset

ntt_2:
    ADD     R2, R6, R7 // end
    MOVWU.W 4(R1), R8 // zeta
    MOVW    R6, R9 // j

ntt_3:
    ADD     R2, R9, R10 // j + l
    MOVWU   (R0)(R9<<2), R15 // p[j]
    MOVWU   (R0)(R10<<2), R11 // p[j + l]

    MUL     R11, R8, R11 // x
    MUL     R21, R11, R12 // m
    AND     $0xffffffff, R12, R12
    MADD    R20, R11, R12, R12
    LSR     $32, R12, R12
    ADD     R12, R15, R13
    SUB     R12, R22, R14
    ADD     R14, R15, R14

    MOVW    R13, (R0)(R9<<2) // p[j]
    MOVW    R14, (R0)(R10<<2) // p[j + l]

    ADD     $1, R9, R9
    CMP     R7, R9
    BLT     ntt_3 // j < end

    ADD     R5, R6, R6
    CMP     R4, R6
    BLT     ntt_2 // offset < end

    ADDS    R2>>1, ZR, R2
    BGT     ntt_1 // l > 0

    RET


// func polyInvNTT(p *Poly, invZetas *[N]uint32)
TEXT ·polyInvNTT(SB), NOSPLIT|NOFRAME, $0-16
    MOVD    p+0(FP), R0
    MOVD    invZetas+8(FP), R1

    MOVW    $1, R2 // l
    MOVW    $256, R3 // N
    MOVZW   $0xE001, R20 // Q
    MOVKW   $(0x7F<<16), R20
    MOVZW   $0xDFFF, R21 // Qinv
    MOVKW   $(0xFC7F<<16), R21

    LSL     $8, R20, R22 // Q << 8
    MOVW    $0xA3FA, R23 // ROver256

invntt_1:
    SUB     R2, R3, R4 // end
    LSL     $1, R2, R5 // step
    MOVW    $0, R6 // offset

invntt_2:
    ADD     R2, R6, R7 // end
    MOVWU.P 4(R1), R8 // zeta
    MOVW    R6, R9 // j

invntt_3:
    ADD     R2, R9, R10 // j + l
    MOVWU   (R0)(R9<<2), R11 // p[j]
    MOVWU   (R0)(R10<<2), R12 // p[j + l]

    ADD     R12, R11, R13 // p[j] + p[j+l]
    ADDW    R22, R11, R11
    SUBW    R12, R11, R11
    MUL     R11, R8, R11 // x
    MUL     R21, R11, R12 // m
    AND     $0xffffffff, R12, R12
    MADD    R20, R11, R12, R12
    LSR     $32, R12, R14

    MOVWU    R13, (R0)(R9<<2) // p[j]
    MOVWU    R14, (R0)(R10<<2) // p[j + l]

    ADD     $1, R9, R9
    CMP     R7, R9
    BLT     invntt_3 // j < end

    ADD     R5, R6, R6
    CMP     R4, R6
    BLT     invntt_2 // offset < end

    LSL     $1, R2, R2
    CMP     R3, R2
    BLT     invntt_1 // l < N

    MOVW    $256, R2
    MOVD    R0, R1

invntt_4:
    MOVWU.P 4(R0), R3 // p[j]
    MOVWU.P 4(R0), R4 // p[j+1]
    MOVWU.P 4(R0), R5 // p[j+2]
    MOVWU.P 4(R0), R6 // p[j+3]
    MOVWU.P 4(R0), R7 // p[j+4]
    MOVWU.P 4(R0), R8 // p[j+5]
    MOVWU.P 4(R0), R9 // p[j+6]
    MOVWU.P 4(R0), R10 // p[j+7]

    // x = ROver256 * p[j]
    MUL     R23, R3, R3
    MUL     R23, R4, R4
    MUL     R23, R5, R5
    MUL     R23, R6, R6
    MUL     R23, R7, R7
    MUL     R23, R8, R8
    MUL     R23, R9, R9
    MUL     R23, R10, R10

    // m := (x * Qinv) & 0xffffffff
    MUL     R21, R3, R11
    MUL     R21, R4, R12
    MUL     R21, R5, R13
    MUL     R21, R6, R14
    MUL     R21, R7, R15
    MUL     R21, R8, R16
    MUL     R21, R9, R17
    MUL     R21, R10, R19
    AND     $0xffffffff, R11, R11
    AND     $0xffffffff, R12, R12
    AND     $0xffffffff, R13, R13
    AND     $0xffffffff, R14, R14
    AND     $0xffffffff, R15, R15
    AND     $0xffffffff, R16, R16
    AND     $0xffffffff, R17, R17
    AND     $0xffffffff, R19, R19

    // (x + m*uint64(Q)) >> 32
    MADD    R20, R3, R11, R3
    MADD    R20, R4, R12, R4
    MADD    R20, R5, R13, R5
    MADD    R20, R6, R14, R6
    MADD    R20, R7, R15, R7
    MADD    R20, R8, R16, R8
    MADD    R20, R9, R17, R9
    MADD    R20, R10, R19, R10
    LSR     $32, R3, R3
    LSR     $32, R4, R4
    LSR     $32, R5, R5
    LSR     $32, R6, R6
    LSR     $32, R7, R7
    LSR     $32, R8, R8
    LSR     $32, R9, R9
    LSR     $32, R10, R10

    MOVWU.P R3, 4(R1) // p[j]
    MOVWU.P R4, 4(R1) // p[j+1]
    MOVWU.P R5, 4(R1) // p[j+2]
    MOVWU.P R6, 4(R1) // p[j+3]
    MOVWU.P R7, 4(R1) // p[j+4]
    MOVWU.P R8, 4(R1) // p[j+5]
    MOVWU.P R9, 4(R1) // p[j+6]
    MOVWU.P R10, 4(R1) // p[j+7]

    SUBS    $8, R2, R2
    BGT     invntt_4

    RET


// func polyPackLe16(p *Poly, buf []byte)
TEXT ·polyPackLe16(SB), NOSPLIT|NOFRAME, $0-32
    MOVD    p+0(FP), R0
    MOVD    buf+8(FP), R1

    MOVW    $8, R3 // loop counter
    VMOVQ   $0x1c0c180814041000, $0x3c2c382834243020, V15 // lookup table index (goal is to extract only the lower byte)

packLe16:
    VLD4.P  (64)(R0), [V0.S4, V1.S4, V2.S4, V3.S4]
    VLD4.P  (64)(R0), [V4.S4, V5.S4, V6.S4, V7.S4]

    VSHL    $4, V1.S4, V1.S4
    VSHL    $4, V3.S4, V3.S4
    VSHL    $4, V5.S4, V5.S4
    VSHL    $4, V7.S4, V7.S4

    VORR    V1.B16, V0.B16, V10.B16
    VORR    V3.B16, V2.B16, V11.B16
    VORR    V5.B16, V4.B16, V12.B16
    VORR    V7.B16, V6.B16, V13.B16

    VTBL    V15.B16, [V10.B16, V11.B16, V12.B16, V13.B16], V16.B16

    VST1.P  [V16.B16], (16)(R1)

    SUBS    $1, R3, R3
    BGT     packLe16

    RET


// func polyAdd(p, a, b *Poly)
TEXT ·polyAdd(SB), NOSPLIT|NOFRAME, $0-24
    MOVD    p+0(FP), R0
    MOVD    a+8(FP), R1
    MOVD    b+16(FP), R2

    MOVW    $16, R3 // loop counter

add:
    VLD1.P  (64)(R1), [V0.S4, V1.S4, V2.S4, V3.S4]
    VLD1.P  (64)(R2), [V4.S4, V5.S4, V6.S4, V7.S4]

    VADD    V4.S4, V0.S4, V8.S4
    VADD    V5.S4, V1.S4, V9.S4
    VADD    V6.S4, V2.S4, V10.S4
    VADD    V7.S4, V3.S4, V11.S4

    VST1.P  [V8.S4, V9.S4, V10.S4, V11.S4], (64)(R0)

    SUBS    $1, R3, R3
    BGT     add

    RET


// func polySub(p, a, b *Poly)
TEXT ·polySub(SB), NOSPLIT|NOFRAME, $0-24
    MOVD    p+0(FP), R0
    MOVD    a+8(FP), R1
    MOVD    b+16(FP), R2

    MOVW    $16, R3 // loop counter

    // (Q = 8380417) << 1
    MOVZW   $0xC002, R4
    MOVKW   $(0xFF<<16), R4
    VDUP    R4, V12.S4

sub:
    VLD1.P  (64)(R1), [V0.S4, V1.S4, V2.S4, V3.S4]
    VLD1.P  (64)(R2), [V4.S4, V5.S4, V6.S4, V7.S4]

    VSUB    V4.S4, V12.S4, V4.S4
    VSUB    V5.S4, V12.S4, V5.S4
    VSUB    V6.S4, V12.S4, V6.S4
    VSUB    V7.S4, V12.S4, V7.S4

    VADD    V4.S4, V0.S4, V8.S4
    VADD    V5.S4, V1.S4, V9.S4
    VADD    V6.S4, V2.S4, V10.S4
    VADD    V7.S4, V3.S4, V11.S4

    VST1.P  [V8.S4, V9.S4, V10.S4, V11.S4], (64)(R0)

    SUBS    $1, R3, R3
    BGT     sub

    RET


// func polyMulBy2toD(p, q *Poly)
TEXT ·polyMulBy2toD(SB), NOSPLIT|NOFRAME, $0-16
    MOVD    p+0(FP), R0
    MOVD    q+8(FP), R1

    MOVW    $16, R2

mulBy2toD:
    VLD1.P  (64)(R1), [V0.S4, V1.S4, V2.S4, V3.S4]

    VSHL    $13, V0.S4, V0.S4
    VSHL    $13, V1.S4, V1.S4
    VSHL    $13, V2.S4, V2.S4
    VSHL    $13, V3.S4, V3.S4

    VST1.P  [V0.S4, V1.S4, V2.S4, V3.S4], (64)(R0)

    SUBS    $1, R2, R2
    BGT     mulBy2toD

    RET


// TODO: try to find a simpler way to achieve the same logic
// func polyNormalizeAssumingLe2Q(p *Poly)
TEXT ·polyNormalizeAssumingLe2Q(SB), NOSPLIT|NOFRAME, $0-8
    MOVD    p+0(FP), R0

    MOVD    $16, R2 // loop counter

    // Q = 8380417
    MOVZW   $0xE001, R3
    MOVKW   $(0x7F<<16), R3
    VDUP    R3, V12.S4

normalize_block:
    VLD1    (R0), [V0.S4, V1.S4, V2.S4, V3.S4]

    VSUB    V12.S4, V0.S4, V0.S4
    VSUB    V12.S4, V1.S4, V1.S4
    VSUB    V12.S4, V2.S4, V2.S4
    VSUB    V12.S4, V3.S4, V3.S4

    WORD    $0x4ea0a804 // cmlt    v4.4s, v0.4s, #0
    WORD    $0x4ea0a825 // cmlt    v5.4s, v1.4s, #0
    WORD    $0x4ea0a846 // cmlt    v6.4s, v2.4s, #0
    WORD    $0x4ea0a867 // cmlt    v7.4s, v3.4s, #0

    VAND    V12.B16, V4.B16, V4.B16
    VAND    V12.B16, V5.B16, V5.B16
    VAND    V12.B16, V6.B16, V6.B16
    VAND    V12.B16, V7.B16, V7.B16

    VADD    V4.S4, V0.S4, V0.S4
    VADD    V5.S4, V1.S4, V1.S4
    VADD    V6.S4, V2.S4, V2.S4
    VADD    V7.S4, V3.S4, V3.S4

    VST1.P  [V0.S4, V1.S4, V2.S4, V3.S4], (64)(R0)

    SUBS    $1, R2, R2
    BGT     normalize_block

    RET


// TODO: try to find a simpler way to achieve the same logic
// func polyPower2Round(p, p0PlusQ, p1 *Poly)
TEXT ·polyPower2Round(SB), NOSPLIT|NOFRAME, $0-24
    MOVD    p+0(FP), R0
    MOVD    p0PlusQ+8(FP), R1
    MOVD    p1+16(FP), R2

    MOVZW   $0xE001, R3 // Q
    MOVKW   $(0x7F<<16), R3
    MOVW    $0x1000, R4 // (1 << (D - 1))
    SUB     $1, R4, R5 // (1 << (D - 1)) - 1
    ADD     $1, R4, R6 // (1 << (D - 1)) + 1
    LSL     $1, R4, R7 // (1 << D)
    SUB     $1, R7, R8 // (1 << D) - 1

    VDUP    R3, V13.S4
    VDUP    R4, V14.S4
    VDUP    R5, V15.S4
    VDUP    R6, V16.S4
    VDUP    R7, V17.S4
    VDUP    R8, V18.S4

    MOVW    $16, R9 // loop counter

power2round:
    VLD1.P  (64)(R0), [V0.S4, V1.S4, V2.S4, V3.S4]

    // a0 := p & ((1 << D) - 1)
    VAND    V18.B16, V0.B16, V4.B16
    VAND    V18.B16, V1.B16, V5.B16
    VAND    V18.B16, V2.B16, V6.B16
    VAND    V18.B16, V3.B16, V7.B16

    // a0 -= (1 << (D - 1)) + 1
    VSUB    V16.S4, V4.S4, V4.S4
    VSUB    V16.S4, V5.S4, V5.S4
    VSUB    V16.S4, V6.S4, V6.S4
    VSUB    V16.S4, V7.S4, V7.S4

    // a0 += uint32(int32(a0)>>31) & (1 << D)
    WORD    $0x4f210488 // sshr    v8.4s, v4.4s, #31
    WORD    $0x4f2104a9 // sshr    v9.4s, v5.4s, #31
    WORD    $0x4f2104ca // sshr    v10.4s, v6.4s, #31
    WORD    $0x4f2104eb // sshr    v11.4s, v7.4s, #31

    VAND    V17.B16, V8.B16, V8.B16
    VAND    V17.B16, V9.B16, V9.B16
    VAND    V17.B16, V10.B16, V10.B16
    VAND    V17.B16, V11.B16, V11.B16

    VADD    V8.S4, V4.S4, V4.S4
    VADD    V9.S4, V5.S4, V5.S4
    VADD    V10.S4, V6.S4, V6.S4
    VADD    V11.S4, V7.S4, V7.S4

    // a0 -= (1 << (D - 1)) - 1
    VSUB    V15.S4, V4.S4, V4.S4
    VSUB    V15.S4, V5.S4, V5.S4
    VSUB    V15.S4, V6.S4, V6.S4
    VSUB    V15.S4, V7.S4, V7.S4

    // a1 := (a - a0)
    VSUB    V4.S4, V0.S4, V0.S4
    VSUB    V5.S4, V1.S4, V1.S4
    VSUB    V6.S4, V2.S4, V2.S4
    VSUB    V7.S4, V3.S4, V3.S4

    // a0plusQ = Q + a0
    VADD    V4.S4, V13.S4, V4.S4
    VADD    V5.S4, V13.S4, V5.S4
    VADD    V6.S4, V13.S4, V6.S4
    VADD    V7.S4, V13.S4, V7.S4

    // a1 >>= 13
    VUSHR   $13, V0.S4, V0.S4
    VUSHR   $13, V1.S4, V1.S4
    VUSHR   $13, V2.S4, V2.S4
    VUSHR   $13, V3.S4, V3.S4

    VST1.P  [V4.S4, V5.S4, V6.S4, V7.S4], (64)(R1)
    VST1.P  [V0.S4, V1.S4, V2.S4, V3.S4], (64)(R2)

    SUBS    $1, R9, R9
    BGT     power2round

    RET


// TODO: try to find a simpler way to achieve the same logic
// func polyReduceLe2Q(p *Poly)
TEXT ·polyReduceLe2Q(SB), NOSPLIT|NOFRAME, $0-8
    MOVD    p+0(FP), R0

    MOVW    $16, R1 // loop counter
    MOVW    $0x7FFFFF, R2 // 2²³ - 1

    VDUP    R2, V12.S4

reduceLe2Q:
    VLD1    (R0), [V0.S4, V1.S4, V2.S4, V3.S4]

    // x1 := x >> 23
    VUSHR   $23, V0.S4, V4.S4
    VUSHR   $23, V1.S4, V5.S4
    VUSHR   $23, V2.S4, V6.S4
    VUSHR   $23, V3.S4, V7.S4

    // x2 := x & 0x7FFFFF
    VAND    V12.B16, V0.B16, V8.B16
    VAND    V12.B16, V1.B16, V9.B16
    VAND    V12.B16, V2.B16, V10.B16
    VAND    V12.B16, V3.B16, V11.B16

    // x = x1 << 13
    VSHL    $13, V4.S4, V0.S4
    VSHL    $13, V5.S4, V1.S4
    VSHL    $13, V6.S4, V2.S4
    VSHL    $13, V7.S4, V3.S4

    // x = x2 + x
    VADD    V0.S4, V8.S4, V0.S4
    VADD    V1.S4, V9.S4, V1.S4
    VADD    V2.S4, V10.S4, V2.S4
    VADD    V3.S4, V11.S4, V3.S4

    // x3 - x1
    VSUB    V4.S4, V0.S4, V0.S4
    VSUB    V5.S4, V1.S4, V1.S4
    VSUB    V6.S4, V2.S4, V2.S4
    VSUB    V7.S4, V3.S4, V3.S4

    VST1.P  [V0.S4, V1.S4, V2.S4, V3.S4], (64)(R0)

    SUBS    $1, R1, R1
    BGT     reduceLe2Q

    RET


// TODO: try to find a simpler way to achieve the same logic
// func polyNormalize(p *Poly)
TEXT ·polyNormalize(SB), NOSPLIT|NOFRAME, $0-8
    MOVD    p+0(FP), R0

    MOVW    $16, R1 // loop counter
    MOVW    $0x7FFFFF, R2 // 2²³ - 1
    MOVW    $8380417, R3 // Q

    VDUP    R2, V12.S4
    VDUP    R3, V13.S4

normalize:
    VLD1    (R0), [V0.S4, V1.S4, V2.S4, V3.S4]

    // x1 := x >> 23
    VUSHR   $23, V0.S4, V4.S4
    VUSHR   $23, V1.S4, V5.S4
    VUSHR   $23, V2.S4, V6.S4
    VUSHR   $23, V3.S4, V7.S4

    // x2 := x & 0x7FFFFF
    VAND    V12.B16, V0.B16, V8.B16
    VAND    V12.B16, V1.B16, V9.B16
    VAND    V12.B16, V2.B16, V10.B16
    VAND    V12.B16, V3.B16, V11.B16

    // x = x1 << 13
    VSHL    $13, V4.S4, V0.S4
    VSHL    $13, V5.S4, V1.S4
    VSHL    $13, V6.S4, V2.S4
    VSHL    $13, V7.S4, V3.S4

    // x = x2 + x
    VADD    V0.S4, V8.S4, V0.S4
    VADD    V1.S4, V9.S4, V1.S4
    VADD    V2.S4, V10.S4, V2.S4
    VADD    V3.S4, V11.S4, V3.S4

    // x = x - x1
    VSUB    V4.S4, V0.S4, V0.S4
    VSUB    V5.S4, V1.S4, V1.S4
    VSUB    V6.S4, V2.S4, V2.S4
    VSUB    V7.S4, V3.S4, V3.S4

    // x = x - Q
    VSUB    V13.S4, V0.S4, V0.S4
    VSUB    V13.S4, V1.S4, V1.S4
    VSUB    V13.S4, V2.S4, V2.S4
    VSUB    V13.S4, V3.S4, V3.S4

    // mask = uint32(int32(x) >> 31)
    WORD    $0x4ea0a804 // cmlt    v4.4s, v0.4s, #0
    WORD    $0x4ea0a825 // cmlt    v5.4s, v1.4s, #0
    WORD    $0x4ea0a846 // cmlt    v6.4s, v2.4s, #0
    WORD    $0x4ea0a867 // cmlt    v7.4s, v3.4s, #0

    // mask = mask & Q
    VAND    V13.B16, V4.B16, V4.B16
    VAND    V13.B16, V5.B16, V5.B16
    VAND    V13.B16, V6.B16, V6.B16
    VAND    V13.B16, V7.B16, V7.B16

    // x + mask
    VADD    V4.S4, V0.S4, V0.S4
    VADD    V5.S4, V1.S4, V1.S4
    VADD    V6.S4, V2.S4, V2.S4
    VADD    V7.S4, V3.S4, V3.S4

    VST1.P  [V0.S4, V1.S4, V2.S4, V3.S4], (64)(R0)

    SUBS    $1, R1, R1
    BGT     normalize

    RET


// TODO: try to find a simpler way to achieve the same logic
// func polyExceeds(p *Poly, bound uint32) bool
TEXT ·polyExceeds(SB), NOSPLIT|NOFRAME, $0-24
    MOVD    p+0(FP), R0
    MOVW    bound+8(FP), R1

    MOVW    $16, R3 // loop counter
    MOVW    $4190208, R4 // (Q - 1) >> 1

    VDUP    R4, V13.S4
    VDUP    R1, V14.S4

exceeds:
    VLD1.P  (64)(R0), [V0.S4, V1.S4, V2.S4, V3.S4]

    VSUB    V0.S4, V13.S4, V0.S4
    VSUB    V1.S4, V13.S4, V1.S4
    VSUB    V2.S4, V13.S4, V2.S4
    VSUB    V3.S4, V13.S4, V3.S4

    WORD    $0x4f210404 //  sshr    v4.4s, v0.4s, #31
    WORD    $0x4f210425 //  sshr    v5.4s, v1.4s, #31
    WORD    $0x4f210446 //  sshr    v6.4s, v2.4s, #31
    WORD    $0x4f210467 //  sshr    v7.4s, v3.4s, #31

    VEOR    V4.B16, V0.B16, V0.B16
    VEOR    V5.B16, V1.B16, V1.B16
    VEOR    V6.B16, V2.B16, V2.B16
    VEOR    V7.B16, V3.B16, V3.B16

    VSUB    V0.S4, V13.S4, V0.S4
    VSUB    V1.S4, V13.S4, V1.S4
    VSUB    V2.S4, V13.S4, V2.S4
    VSUB    V3.S4, V13.S4, V3.S4

    WORD    $0x6eae3c00 //  cmhs    v0.4s, v0.4s, v14.4s
    WORD    $0x6eae3c21 //  cmhs    v1.4s, v1.4s, v14.4s
    WORD    $0x6eae3c42 //  cmhs    v2.4s, v2.4s, v14.4s
    WORD    $0x6eae3c63 //  cmhs    v3.4s, v3.4s, v14.4s

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

    CMP     ZR, R10
    BGT     exceeded

    SUBS    $1, R3, R3
    BGT     exceeds

    MOVW    $0, R20 // no value exceeded the bound
    MOVB    R20, ret+16(FP)

    RET

exceeded:
    MOVW    $1, R20 // at least one value exceeded the bound
    MOVB    R20, ret+16(FP)

    RET
