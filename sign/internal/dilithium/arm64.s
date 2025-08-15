//go:build arm64 && !purego

#include "textflag.h"

// func polyAddARM64(p, a, b *Poly)
TEXT ·polyAddARM64(SB), NOSPLIT|NOFRAME, $0-24
    MOVD    p+0(FP), R0
    MOVD    a+8(FP), R1
    MOVD    b+16(FP), R2

    // loop counter (each iteration processes 16 elements so 16 * 16 = 256 = N)
    // manually unrolling could also be done, for now skipped
    MOVW    $16, R3

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

    MOVW    $8, R3 // loop counter
    VMOVQ   $0x1c0c180814041000, $0x3c2c382834243020, V15 // lookup table index

loop:
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
    BGT     loop

    RET
