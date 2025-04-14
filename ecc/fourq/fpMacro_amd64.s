// CHECK_BMI2 triggers bmi2 if supported,
// otherwise it fallbacks to legacy code.
#define CHECK_BMI2(label, legacy, bmi2) \
    CMPB ·hasBMI2(SB), $0 \
    JE label              \
    bmi2                  \
    RET                   \
    label:                \
    legacy                \
    RET

#define _fpReduce(c0, c1) \
    BTRQ $63, c1          \
    ADCQ  $0, c0          \
    ADCQ  $0, c1

// _fpMod: c = c mod p
// Uses: AX, DX, FLAGS
// Instr: x86_64
#define _fpMod(c) \
    MOVQ 0+c, AX \
    MOVQ 8+c, DX \
    SUBQ ·modulusP+0(SB), AX \
    SBBQ ·modulusP+8(SB), DX \
    BTRQ $63, DX  \
    SBBQ  $0, AX  \
    SBBQ  $0, DX  \
    _fpReduce(AX, DX) \
    _fpReduce(AX, DX) \
    MOVQ AX, 0+c  \
    MOVQ DX, 8+c

// _fpAdd: c = a + b
// Uses: AX, DX, FLAGS
// Instr: x86_64
#define _fpAdd(c,a,b) \
    MOVQ 0+a, AX      \
    MOVQ 8+a, DX      \
    ADDQ 0+b, AX      \
    ADCQ 8+b, DX      \
    _fpReduce(AX, DX) \
    MOVQ AX, 0+c      \
    MOVQ DX, 8+c

// _fpSub: c = a - b
// Uses: AX, DX, FLAGS
// Instr: x86_64
#define _fpSub(c,a,b) \
    MOVQ 0+a, AX      \
    MOVQ 8+a, DX      \
    SUBQ 0+b, AX      \
    SBBQ 8+b, DX      \
    BTRQ $63, DX      \
    SBBQ  $0, AX      \
    SBBQ  $0, DX      \
    MOVQ AX, 0+c      \
    MOVQ DX, 8+c

#define _fpMulLeg(C2, C1, C0, a, b) \
    MOVQ   $0, C2 \
    MOVQ  0+b, CX \
    MOVQ  0+a, AX \
    MULQ CX       \
    MOVQ AX, C0   \
    MOVQ DX, C1   \
    MOVQ  8+a, AX \
    MULQ CX       \
    SHLQ $1,DX    \
    ADDQ DX,C0    \
    ADCQ AX, C1   \
    ADCQ $0, C2   \
    MOVQ  8+b, CX \
    MOVQ  0+a, AX \
    MULQ CX       \
    SHLQ $1,DX    \
    ADDQ DX,C0    \
    ADCQ AX, C1   \
    ADCQ $0, C2   \
    MOVQ  8+a, AX \
    MULQ CX       \
    SHLQ $1,AX,DX \
    SHLQ $1,AX    \
    ADDQ AX,C0    \
    ADCQ DX, C1   \
    ADCQ $0, C2
