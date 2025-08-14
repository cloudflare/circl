//go:build arm64 && !purego

#include "textflag.h"

// func polyAdd(p, a, b *Poly)
TEXT ·polyAdd(SB), NOSPLIT|NOFRAME, $0-24
    MOVD    p+0(FP), R0
    MOVD    a+8(FP), R1
    MOVD    b+16(FP), R2

    // loop counter (each iterations processes 16 elements so 16 * 16 = 256 = N)
    // manually unrolling could also be done, for now skipped
    MOVW    $16, R3

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
