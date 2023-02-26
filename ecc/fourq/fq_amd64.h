#include "fp_amd64.h"

#define _fqAdd(c,a,b)      \
    _fpAdd( 0+c, 0+a, 0+b) \
    _fpAdd(16+c,16+a,16+b)

#define _fqSub(c,a,b)      \
    _fpSub( 0+c, 0+a, 0+b) \
    _fpSub(16+c,16+a,16+b)

#define _fqMulBmi2(c, a, b) \
    MOVL $0, R15 \
    \ // T0 = a0 * b0, R11:R10:R9:R8 <- 0+ra:8+ra * 0+rb:8+rb
    MOVQ 0+b, DX \
    MULXQ 0+a, R8, R9 \
    MULXQ 8+a, R10, AX \
    ADDQ R10, R9 \
    MOVQ 8+b, DX \
    MULXQ 8+a, R10, R11 \
    ADCQ AX, R10 \
    MULXQ 0+a, DX, AX \
    ADCQ $0, R11 \
    ADDQ DX, R9 \
    \
    \ // T1 = a1 * b1, R15:R14:R13:R12 <- 16+ra:24+ra * 16+rb:24+rb
    MOVQ 16+b, DX \
    MULXQ 16+a, R12, R13 \
    ADCQ AX, R10 \
    MULXQ 24+a, R14, AX \
    ADCQ $0, R11 \
    MOVQ 24+b, DX \
    ADDQ R14, R13 \
    MULXQ 24+a, R14, R15 \
    ADCQ AX, R14 \
    ADCQ $0, R15 \
    MULXQ 16+a, DX, AX \
    ADDQ DX, R13 \
    ADCQ AX, R14 \
    ADCQ $0, R15 \
    \
    \ // c0 = T0 - T1 = a0*b0 - a1*b1
    SUBQ R12, R8 \
    SBBQ R13, R9 \
    SBBQ R14, R10 \
    SBBQ R15, R11 \
    \
    SHLQ $1, R10, R11 \
    SHLQ $1, R9, R10 \
    MOVQ 16+b, DX \
    BTRQ $63, R9 \
    \
    \ // T0 = a0 * b1, R15:R14:R13:R12 <- 0+ra:8+ra * 16+rb:24+rb
    MULXQ 0+a, R12, R13 \
    BTRQ $63, R11 \
    SBBQ $0, R10 \
    SBBQ $0, R11 \
    MULXQ 8+a, R14, AX \
    ADDQ R14, R13 \
    MOVQ 24+b, DX \
    MULXQ 8+a, R14, R15 \
    ADCQ AX, R14 \
    ADCQ $0, R15 \
    MULXQ 0+a, DX, AX \
    ADDQ DX, R13 \
    ADCQ AX, R14 \
    ADCQ $0, R15 \
    \
    \ // Reducing and storing c0
    ADDQ R8, R10 \
    ADCQ R9, R11 \
    BTRQ $63, R11 \
    ADCQ $0, R10 \
    ADCQ $0, R11 \
    \
    \ // T1 = a1 * b0, R12:R11:R10:R9 <- 16+ra:24+ra * 0+rb:8+rb
    MOVQ 0+b, DX \
    MULXQ 16+a, R8, R9 \
    MOVQ R10, 0+c \
    MULXQ 24+a, R10, AX \
    ADDQ R10, R9 \
    MOVQ 8+b, DX \
    MOVQ R11, 8+c \
    MULXQ 24+a, R10, R11 \
    ADCQ AX, R10 \
    ADCQ $0, R11 \
    MULXQ 16+a, DX, AX \
    ADDQ DX, R9 \
    ADCQ AX, R10 \
    ADCQ $0, R11 \
    \
    \ // c1 = T0 + T1 = a0*b1 + a1*b0
    ADDQ R12, R8 \
    ADCQ R13, R9 \
    ADCQ R14, R10 \
    ADCQ R15, R11 \
    \
    \ // Reducing and storing c1
    SHLQ $1, R10, R11 \
    SHLQ $1, R9, R10 \
    BTRQ $63, R9 \
    BTRQ $63, R11 \
    ADCQ R10, R8 \
    ADCQ R11, R9 \
    BTRQ $63, R9 \
    ADCQ $0, R8 \
    ADCQ $0, R9 \
    MOVQ R8, 16+c \
    MOVQ R9, 24+c

#define _fqMulLeg(c, a, b) \
    _fpMulLeg(R10, R9, R8, 0+a, 0+b) \
    _fpMulLeg(R13,R12,R11,16+a,16+b) \
    MOVQ  $0,R14 \
    SUBQ R11, R8 \
    SBBQ R12, R9 \
    SBBQ R13,R10 \
    SBBQ  $0,R14 \
    SHLQ  $1,R10 \
    BTRQ $63, R9 \
    ADCQ R10, R8 \
    ADCQ R14, R9 \
    MOVQ R8, R14 \
    MOVQ R9, R15 \
    _fpMulLeg(R10, R9, R8, 0+a,16+b) \
    _fpMulLeg(R13,R12,R11,16+a, 0+b) \
    ADDQ R11, R8 \
    ADCQ R12, R9 \
    ADCQ R13,R10 \
    SHLQ  $1,R10 \
    BTRQ $63, R9 \
    ADCQ R10, R8 \
    ADCQ  $0, R9 \
    MOVQ R14, 0+c \
    MOVQ R15, 8+c \
    MOVQ  R8,16+c \
    MOVQ  R9,24+c

#define _fqSqrBmi2(c,a) \
    \ // t0 = R9:R8 = a0 + a1, R14:CX = a1
    MOVQ 0+a, R10 \
    MOVQ 16+a, R14 \
    SUBQ R14, R10 \
    MOVQ 8+a, R11 \
    MOVQ 24+a, CX \
    SBBQ CX, R11 \
    \
    BTRQ $63, R11 \
    SBBQ $0, R10 \
    \
    \ // t1 = R11:R10 = a0 - a1
    MOVQ R10, DX \
    MOVQ 0+a, R8 \
    ADDQ R14, R8 \
    MOVQ 8+a, R9 \
    ADCQ CX, R9 \
    \
    \ //  c0 = t0 * t1 = (a0 + a1)*(a0 - a1), CX:R14:R13:R12 <- R9:R8 * R11:R10
    MULXQ R8, R12, R13 \
    SBBQ $0, R11 \
    MULXQ R9, R14, AX \
    MOVQ R11, DX \
    ADDQ R14, R13 \
    MULXQ R9, R14, CX \
    MOVQ 8+a, R9 \
    ADCQ AX, R14 \
    ADCQ $0, CX \
    MULXQ R8, DX, AX \
    MOVQ 0+a, R8 \
    ADDQ DX, R13 \
    ADCQ AX, R14 \
    ADCQ $0, CX \
    \
    \ // t2 = R9:R8 = 2*a0
    ADDQ R8, R8 \
    ADCQ R9, R9 \
    \
    \ // Reducing and storing c0
    SHLQ $1, R14, CX \
    SHLQ $1, R13, R14 \
    BTRQ $63, R13 \
    BTRQ $63, CX \
    ADCQ R14, R12 \
    ADCQ CX, R13 \
    BTRQ $63, R13 \
    ADCQ $0, R12 \
    ADCQ $0, R13 \
    MOVQ R12, 0+c \
    MOVQ R13, 8+c \
    \
    \ //  c1 = 2a0 * a1, CX:R14:R11:R10 <- R9:R8 * 16+ra:24+ra
    MOVQ 16+a, DX \
    MULXQ R8, R10, R11 \
    MULXQ R9, R14, AX \
    ADDQ R14, R11 \
    MOVQ 24+a, DX \
    MULXQ R9, R14, CX \
    ADCQ AX, R14 \
    ADCQ $0, CX \
    MULXQ R8, DX, AX \
    ADDQ DX, R11 \
    ADCQ AX, R14 \
    ADCQ $0, CX \
    \
    \ // Reduce and store c1
    SHLQ $1, R14, CX \
    SHLQ $1, R11, R14 \
    BTRQ $63, R11 \
    BTRQ $63, CX \
    ADCQ R14, R10 \
    ADCQ CX, R11 \
    BTRQ $63, R11 \
    ADCQ $0, R10 \
    ADCQ $0, R11 \
    MOVQ R10, 16+c \
    MOVQ R11, 24+c

#define _fqSqrLeg(c,a) _fqMulLeg(c,a,a)
