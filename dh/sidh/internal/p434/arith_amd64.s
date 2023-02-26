// +build amd64,!noasm

#include "textflag.h"

// p434
#define P434_0 $0xFFFFFFFFFFFFFFFF
#define P434_3 $0xFDC1767AE2FFFFFF
#define P434_4 $0x7BC65C783158AEA3
#define P434_5 $0x6CFC5FD681C52056
#define P434_6 $0x0002341F27177344

// p434 x 2
#define P434X2_0 $0xFFFFFFFFFFFFFFFE
#define P434X2_1 $0xFFFFFFFFFFFFFFFF
#define P434X2_3 $0xFB82ECF5C5FFFFFF
#define P434X2_4 $0xF78CB8F062B15D47
#define P434X2_5 $0xD9F8BFAD038A40AC
#define P434X2_6 $0x0004683E4E2EE688

// Redefine P434p1Zeros
#define P434_P1_ZEROS 3

// Performs schoolbook multiplication of 128-bit with 256-bit
// number. Uses MULX, ADOX, ADCX instruction.
//
// Uses registers: DX,AX
// Calculates:
//   (I0,I1) x [M1][0,1,2,3] = (T0,T1,T2,T3,T4,T5)
//   |-128-| x |--- 256 ---| = |------ 384 ------|
// Assuming the first digit multiplication was already performed.
#define MULX128x256(I1, M1, T1, T2, T3, T4, T5)    \
    MOVQ    M1+ 8(SB), AX       \
    MULXQ   AX, T4, T2          \
    XORQ    AX, AX              \
    MOVQ    M1+16(SB), AX       \
    MULXQ   AX, T5, T3          \
    ADOXQ   T4, T1              \ // T1: interm1
    ADOXQ   T5, T2              \ // T2: interm2
    MOVQ    M1+24(SB), AX       \
    MULXQ   AX, T5, T4          \
    ADOXQ   T5, T3              \ // T3: interm3
    MOVL    $0, AX              \
    ADOXQ   AX, T4              \ // T4: interm4
    \
    XORQ    AX, AX              \
    MOVQ    I1, DX              \
    MOVQ    M1+ 0(SB), AX       \
    MULXQ   AX, T5, I1          \ // T0 <- C0
    ADCXQ   T5, T1              \
    ADCXQ   I1, T2              \ // T1 <- C1
    MOVQ    M1+ 8(SB), AX       \
    MULXQ   AX, I1, T5          \
    ADCXQ   T5, T3              \
    ADOXQ   I1, T2              \ // T2 <- C2
    MOVQ    M1+16(SB), AX       \
    MULXQ   AX, I1, T5          \
    ADCXQ   T5, T4              \
    ADOXQ   I1, T3              \ // T3 <- C3
    MOVQ    M1+24(SB), AX       \
    MULXQ   AX, I1, T5          \
    MOVL    $0, AX              \
    ADCXQ   AX, T5              \
    ADOXQ   I1, T4              \ // T4 <- C4
    ADOXQ   AX, T5                // T5 <- C5

// Performs schoolbook multiplication of 64-bit with 256-bit
// number. Uses MULX and ADOX instructions.
//
// Uses registers: DX,AX
// Calculates:
//   (I0) x [M1][0,1,2,3] = (T0,T1,T2,T3,T4)
//   |64| x |--- 256 ---| = |----- 320 ----|
// Assuming the first digit multiplication was already performed.
#define MULX64x256(M1, T1, T2, T3, T4, T5) \
    MOVQ    M1+ 8(SB), AX       \
    MULXQ   AX, T4, T2          \
    XORQ    AX, AX              \
    MOVQ    M1+16(SB), AX       \
    MULXQ   AX, T5, T3          \
    ADOXQ   T4, T1              \ // T1 <- C1
    ADOXQ   T5, T2              \ // T2 <- C2
    MOVQ    M1+24(SB), AX       \
    MULXQ   AX, T5, T4          \
    ADOXQ   T5, T3              \ // T3 <- C3
    MOVL    $0, AX              \
    ADOXQ   AX, T4                // T4 <- C4

// Performs schoolbook multiplication of two 192-bit numbers
// number. Uses MULX and ADOX instructions.
//
// Uses registers: DX,AX
#define MULX192(IM0,M0,IM1,M1,ID,MDST,T0,T1,T2,T3,T4,T5,T6) \
    MOVQ    (0+IM0)(M0), DX      \
    MULXQ   (0+IM1)(M1), T1, T0  \ // T0:T1 = A0*B0
    MOVQ    T1,(ID+0)(MDST)      \ // MDST0
    MULXQ   (IM1+ 8)(M1), T2, T1 \ // T1:T2 = A0*B1
    XORQ    AX, AX               \
    ADOXQ   T2, T0               \
    MULXQ   (IM1+16)(M1),T3, T2  \ // T2:T3 = A0*B2
    ADOXQ   T3, T1               \
    \
    MOVQ    (IM0+8)(M0), DX      \
    MULXQ   (IM1+0)(M1), T4, T3  \ // T3:T4 = A1*B0
    ADOXQ   AX, T2               \
    XORQ    AX, AX               \
    \
    MULXQ   (IM1+8)(M1), T6, T5  \ // T6:T7 = A1*B1
    ADOXQ   T0, T4               \
    MOVQ    T4,(ID+8)(MDST)      \ // MDST1
    ADCXQ   T6, T3               \
    \
    MULXQ   (IM1+16)(M1),T0, T6  \ // T6:T0 = A1*B2
    ADOXQ   T1, T3               \
    ADCXQ   T0, T5               \
    ADCXQ   AX, T6               \
    ADOXQ   T2, T5               \
    \
    MOVQ    (IM0+16)(M0),DX      \
    MULXQ   (IM1+ 0)(M1), T0, T1 \ // T1:T0 = A2*B0
    ADOXQ   AX, T6               \
    XORQ    AX, AX               \
    \
    MULXQ   (IM1+ 8)(M1), T2, T4 \ // T4:T2 = A2*B1
    ADOXQ   T3, T0               \
    MOVQ    T0, (ID+16)(MDST)    \ // MDST2
    ADCXQ   T5, T1               \
    \
    MULXQ   (IM1+16)(M1),T3, T0  \ // T0:T3 = A2*B2
    ADCXQ   T6, T4               \
    ADCXQ   AX, T0               \
    ADOXQ   T2, T1               \
    ADOXQ   T4, T3               \
    ADOXQ   T0, AX

// Performs schoolbook multiplication of 2 256-bit numbers. Uses
// MULX instruction. Result is stored in 256 bits pointed by $DST.
//
// Uses registers: DX,AX
#define MULX256(IM0,M0,IM1,M1,ID,MDST,T0,T1,T2,T3,T4,T5,T6,T7,T8,T9) \
    MOVQ    (IM0+0)(M0), DX      \
    MULXQ   (IM1+0)(M1), T1, T0  \ // A0*B[0-3]
    MOVQ    T1, (ID+0)(MDST)     \
    MULXQ   (IM1+8)(M1), T2, T1  \
    XORQ    AX, AX               \
    ADOXQ   T2, T0               \
    MULXQ   (IM1+16)(M1),T3, T2  \
    ADOXQ   T3, T1               \
    MULXQ   (IM1+24)(M1),T4, T3  \
    ADOXQ   T4, T2               \
    \
    MOVQ    (IM0+8)(M0), DX      \
    MULXQ   (IM1+0)(M1), T4, T5  \ // A1*B[0-3]
    ADOXQ   AX, T3               \
    XORQ    AX, AX               \
    MULXQ   (IM1+8)(M1), T7, T6  \
    ADOXQ   T0, T4               \
    MOVQ    T4, (ID+8)(MDST)     \
    ADCXQ   T7, T5               \
    MULXQ   (IM1+16)(M1),T8, T7  \
    ADCXQ   T8, T6               \
    ADOXQ   T1, T5               \
    MULXQ   (IM1+24)(M1),T9, T8  \
    ADCXQ   T9, T7               \
    ADCXQ   AX, T8               \
    ADOXQ   T2, T6               \
    \
    MOVQ    (IM0+16)(M0),DX      \ // A2*B[0-3]
    MULXQ   (IM1+ 0)(M1), T0, T1 \
    ADOXQ   T3, T7               \
    ADOXQ   AX, T8               \
    XORQ    AX, AX               \
    MULXQ   (IM1+8)(M1), T3, T2  \
    ADOXQ   T5, T0               \
    MOVQ    T0, (ID+16)(MDST)    \
    ADCXQ   T3, T1               \
    MULXQ   (IM1+16)(M1),T4, T3  \
    ADCXQ   T4, T2               \
    ADOXQ   T6, T1               \
    MULXQ   (IM1+24)(M1),T9, T4  \
    ADCXQ   T9, T3               \
    MOVQ    (IM0+24)(M0),DX      \
    ADCXQ   AX, T4               \
    \
    ADOXQ   T7, T2               \
    ADOXQ   T8, T3               \
    ADOXQ   AX, T4               \
    \
    MULXQ   (IM1+ 0)(M1),  T0, T5\ // A3*B[0-3]
    XORQ    AX,  AX              \
    MULXQ   (IM1+ 8)(M1),  T7, T6\
    ADCXQ   T7,  T5              \
    ADOXQ   T0,  T1              \
    MULXQ   (IM1+16)(M1), T8, T7 \
    ADCXQ   T8,  T6              \
    ADOXQ   T5,  T2              \
    MULXQ   (IM1+24)(M1), T9, T8 \
    ADCXQ   T9,  T7              \
    ADCXQ   AX,  T8              \
    ADOXQ   T6,  T3              \
    ADOXQ   T7,  T4              \
    ADOXQ   AX,  T8              \
    MOVQ    T1,  (ID+24)(MDST)   \
    MOVQ    T2,  (ID+32)(MDST)   \
    MOVQ    T3,  (ID+40)(MDST)   \
    MOVQ    T4,  (ID+48)(MDST)   \
    MOVQ    T8,  (ID+56)(MDST)

// Performs schoolbook multiplication of 64-bit with 256-bit
// number.
//
// Uses registers: DX, AX
#define MUL64x256(IDX,M0,M1,C0,C1,C2,C3,C4,T0) \
    MOVQ   (IDX)(M0), T0 \
    \
    XORQ   C2, C2        \
    MOVQ   M1+0(SB), AX  \
    MULQ   T0            \
    MOVQ   AX, C0        \
    MOVQ   DX, C1        \
    \
    XORQ   C3, C3        \
    MOVQ   M1+8(SB), AX  \
    MULQ   T0            \
    ADDQ   AX, C1        \
    ADCQ   DX, C2        \
    \
    XORQ   C4, C4        \
    MOVQ   M1+16(SB), AX \
    MULQ   T0            \
    ADDQ   AX, C2        \
    ADCQ   DX, C3        \
    \
    MOVQ   M1+24(SB), AX \
    MULQ   T0            \
    ADDQ   AX, C3        \
    ADCQ   DX, C4

// Performs schoolbook multiplication of 128-bit with 256-bit
// number. Destroys RAX and RDX
//
// Uses registers: DX, AX
#define MUL128x256(IDX,M0,M1,C0,C1,C2,C3,C4,C5,T0,T1) \
    \ // A0 x B0
    MOVQ   (IDX+0)(M0), T0 \
    MOVQ   M1+0(SB), AX    \
    MULQ   T0              \
    XORQ   C2, C2          \
    MOVQ   AX, C0          \
    MOVQ   DX, C1          \
    \ // A0 x B1
    MOVQ   M1+8(SB), AX    \
    MULQ   T0              \
    XORQ   C3, C3          \
    ADDQ   AX, C1          \
    ADCQ   DX, C2          \
    \ // A1 x B0
    MOVQ   (IDX+8)(M0), T1 \
    MOVQ   M1+0(SB), AX    \
    MULQ   T1              \
    ADDQ   AX, C1          \
    ADCQ   DX, C2          \
    ADCQ   $0, C3          \
    \ // A0 x B2
    XORQ   C4, C4          \
    MOVQ   M1+16(SB), AX   \
    MULQ   T0              \
    ADDQ   AX, C2          \
    ADCQ   DX, C3          \
    ADCQ   $0, C4          \
    \ // A1 x B1
    MOVQ   M1+8(SB), AX    \
    MULQ   T1              \
    ADDQ   AX, C2          \
    ADCQ   DX, C3          \
    ADCQ   $0, C4          \
    \ // A0 x B3
    MOVQ   M1+24(SB), AX   \
    MULQ   T0              \
    XORQ   C5, C5          \
    ADDQ   AX, C3          \
    ADCQ   DX, C4          \
    ADCQ   $0, C5          \
    \ // A1 x B2
    MOVQ   M1+16(SB), AX   \
    MULQ   T1              \
    ADDQ   AX, C3          \
    ADCQ   DX, C4          \
    ADCQ   $0, C5          \
    \ // A1 x B3
    MOVQ   M1+24(SB), AX   \
    MULQ   T1              \
    ADDQ   AX, C4          \
    ADCQ   DX, C5

//  Montgomery reduction
//  Based on method described in Faz-Hernandez et al. https://eprint.iacr.org/2017/1015
#define REDC_MULX(P1, MUL01, MUL23, MUL45, MUL67) \
    MOVQ 0x0(DI), DX        \
    MOVQ 0x8(DI), R14       \
    MOVQ  P1, AX            \
    MULXQ AX, R8, R9        \
    MUL01                   \
    MOVQ 0x10(DI), DX       \
    MOVQ 0x48(DI), CX       \
    ADDQ   0x18(DI), R8     \
    ADCQ   0x20(DI), R9     \
    ADCQ   0x28(DI), R10    \
    ADCQ   0x30(DI), R11    \
    ADCQ   0x38(DI), R12    \
    ADCQ   0x40(DI), R13    \
    ADCQ   $0, CX           \
    MOVQ  P1, AX            \
    MULXQ AX, BX, BP        \
    MOVQ   R9,   0x0(SI)    \
    MOVQ   R10,  0x8(SI)    \
    MOVQ   R11, 0x10(SI)    \
    MOVQ   R12, 0x18(SI)    \
    MOVQ   R13, 0x20(SI)    \
    MOVQ   CX,  0x28(SI)    \
    MOVQ   0x50(DI), R9     \
    MOVQ   0x58(DI), R10    \
    MOVQ   0x60(DI), R11    \
    MOVQ   0x68(DI), DI     \
    ADCQ   $0, R9           \
    ADCQ   $0, R10          \
    ADCQ   $0, R11          \
    ADCQ   $0, DI           \
    MUL23                   \
    MOVQ 0x0(SI), DX        \
    ADDQ   0x08(SI), BX     \
    ADCQ   0x10(SI), BP     \
    ADCQ   0x18(SI), R12    \
    ADCQ   0x20(SI), R13    \
    ADCQ   0x28(SI), R14    \
    MOVQ   R14, 0x18(SI)    \
    MOVQ   CX, R14          \
    MOVQ   $0, CX           \
    ADCQ   R9, R14          \
    ADCQ   R10, CX          \
    MOVQ  P1, AX            \
    MULXQ AX, R8, R9        \
    MOVQ   BP, 0x0(SI)      \
    MOVQ   R12, 0x8(SI)     \
    MOVQ   R13, 0x10(SI)    \
    ADCQ   $0, R11          \
    ADCQ   $0, DI           \
    MUL45                   \
    MOVQ 0x0(SI), DX        \
    ADDQ   0x8(SI), R8      \
    ADCQ   0x10(SI), R9     \
    ADCQ   0x18(SI), R10    \
    ADCQ   R14, BP          \
    ADCQ   CX, R12          \
    ADCQ   R11, R13         \
    ADCQ   $0, DI           \
    MOVQ  P1, AX            \
    MULXQ AX, R14, BX       \
    MOVQ   R8,   0x0(SI)    \
    MOVQ   R9,   0x8(SI)    \
    MUL67                   \
    ADDQ   R10, R14         \
    ADCQ   BP, BX           \
    ADCQ   R12, R8          \
    ADCQ   R13, R9          \
    ADCQ   DI, R11          \
    MOVQ   R14, 0x10(SI)    \
    MOVQ   BX, 0x18(SI)     \
    MOVQ   R8, 0x20(SI)     \
    MOVQ   R9, 0x28(SI)     \
    MOVQ   R11, 0x30(SI)

#define REDC_MULQ(MUL01, MUL23, MUL45, MUL67) \
    MUL01                   \
    XORQ   CX, CX           \
    ADDQ   0x18(DI), R8     \
    ADCQ   0x20(DI), R9     \
    ADCQ   0x28(DI), R10    \
    ADCQ   0x30(DI), R11    \
    ADCQ   0x38(DI), R12    \
    ADCQ   0x40(DI), R13    \
    ADCQ   0x48(DI), CX     \
    MOVQ   R8, 0x18(DI)     \
    MOVQ   R9, 0x20(DI)     \
    MOVQ   R10, 0x28(DI)    \
    MOVQ   R11, 0x30(DI)    \
    MOVQ   R12, 0x38(DI)    \
    MOVQ   R13, 0x40(DI)    \
    MOVQ   CX, 0x48(DI)     \
    MOVQ   0x50(DI), R8     \
    MOVQ   0x58(DI), R9     \
    MOVQ   0x60(DI), R10    \
    MOVQ   0x68(DI), R11    \
    ADCQ   $0, R8           \
    ADCQ   $0, R9           \
    ADCQ   $0, R10          \
    ADCQ   $0, R11          \
    MOVQ   R8, 0x50(DI)     \
    MOVQ   R9, 0x58(DI)     \
    MOVQ   R10, 0x60(DI)    \
    MOVQ   R11, 0x68(DI)    \
    \
    MUL23                   \
    XORQ   CX, CX           \
    ADDQ   0x28(DI), R8     \
    ADCQ   0x30(DI), R9     \
    ADCQ   0x38(DI), R10    \
    ADCQ   0x40(DI), R11    \
    ADCQ   0x48(DI), R12    \
    ADCQ   0x50(DI), R13    \
    ADCQ   0x58(DI), CX     \
    MOVQ   R8, 0x28(DI)     \
    MOVQ   R9, 0x30(DI)     \
    MOVQ   R10, 0x38(DI)    \
    MOVQ   R11, 0x40(DI)    \
    MOVQ   R12, 0x48(DI)    \
    MOVQ   R13, 0x50(DI)    \
    MOVQ   CX, 0x58(DI)     \
    MOVQ   0x60(DI), R8     \
    MOVQ   0x68(DI), R9     \
    ADCQ   $0, R8           \
    ADCQ   $0, R9           \
    MOVQ   R8, 0x60(DI)     \
    MOVQ   R9, 0x68(DI)     \
    \
    MUL45                   \
    XORQ   CX, CX           \
    ADDQ   0x38(DI), R8     \
    ADCQ   0x40(DI), R9     \
    ADCQ   0x48(DI), R10    \
    ADCQ   0x50(DI), R11    \
    ADCQ   0x58(DI), R12    \
    ADCQ   0x60(DI), R13    \
    ADCQ   0x68(DI), CX     \
    MOVQ   R8,   0x0(SI)    \ // OUT0
    MOVQ   R9,   0x8(SI)    \ // OUT1
    MOVQ   R10, 0x48(DI)    \
    MOVQ   R11, 0x50(DI)    \
    MOVQ   R12, 0x58(DI)    \
    MOVQ   R13, 0x60(DI)    \
    MOVQ   CX, 0x68(DI)     \
    \
    MUL67                   \
    ADDQ   0x48(DI), R8     \
    ADCQ   0x50(DI), R9     \
    ADCQ   0x58(DI), R10    \
    ADCQ   0x60(DI), R11    \
    ADCQ   0x68(DI), R12    \
    MOVQ   R8,  0x10(SI)    \ // OUT2
    MOVQ   R9,  0x18(SI)    \ // OUT3
    MOVQ   R10, 0x20(SI)    \ // OUT4
    MOVQ   R11, 0x28(SI)    \ // OUT5
    MOVQ   R12, 0x30(SI)      // OUT6

TEXT ·cswapP434(SB),NOSPLIT,$0-17

    MOVQ    x+0(FP), DI
    MOVQ    y+8(FP), SI
    MOVB    choice+16(FP), AL   // AL = 0 or 1
    MOVBLZX AL, AX  // AX = 0 or 1
    NEGQ    AX          // AX = 0x00..00 or 0xff..ff
#ifndef CSWAP_BLOCK
#define CSWAP_BLOCK(idx)    \
    MOVQ    (idx*8)(DI), BX \ // BX = x[idx]
    MOVQ    (idx*8)(SI), CX \ // CX = y[idx]
    MOVQ    CX, DX          \ // DX = y[idx]
    XORQ    BX, DX          \ // DX = y[idx] ^ x[idx]
    ANDQ    AX, DX          \ // DX = (y[idx] ^ x[idx]) & mask
    XORQ    DX, BX          \ // BX = (y[idx] ^ x[idx]) & mask) ^ x[idx] = x[idx] or y[idx]
    XORQ    DX, CX          \ // CX = (y[idx] ^ x[idx]) & mask) ^ y[idx] = y[idx] or x[idx]
    MOVQ    BX, (idx*8)(DI) \
    MOVQ    CX, (idx*8)(SI)
#endif
    CSWAP_BLOCK(0)
    CSWAP_BLOCK(1)
    CSWAP_BLOCK(2)
    CSWAP_BLOCK(3)
    CSWAP_BLOCK(4)
    CSWAP_BLOCK(5)
    CSWAP_BLOCK(6)
#ifdef CSWAP_BLOCK
#undef CSWAP_BLOCK
#endif
    RET

TEXT ·cmovP434(SB),NOSPLIT,$0-17

    MOVQ    x+0(FP), DI
    MOVQ    y+8(FP), SI
    MOVB    choice+16(FP), AL   // AL = 0 or 1
    MOVBLZX AL, AX  // AX = 0 or 1
    NEGQ    AX          // AX = 0x00..00 or 0xff..ff
#ifndef CMOV_BLOCK
#define CMOV_BLOCK(idx)    \
    MOVQ    (idx*8)(DI), BX \ // BX = x[idx]
    MOVQ    (idx*8)(SI), DX \ // DX = y[idx]
    XORQ    BX, DX          \ // DX = y[idx] ^ x[idx]
    ANDQ    AX, DX          \ // DX = (y[idx] ^ x[idx]) & mask
    XORQ    DX, BX          \ // BX = (y[idx] ^ x[idx]) & mask) ^ x[idx] = x[idx] or y[idx]
    MOVQ    BX, (idx*8)(DI)
#endif
    CMOV_BLOCK(0)
    CMOV_BLOCK(1)
    CMOV_BLOCK(2)
    CMOV_BLOCK(3)
    CMOV_BLOCK(4)
    CMOV_BLOCK(5)
    CMOV_BLOCK(6)
#ifdef CMOV_BLOCK
#undef CMOV_BLOCK
#endif
    RET

TEXT ·addP434(SB),NOSPLIT,$0-24
    MOVQ    z+0(FP), DX
    MOVQ    x+8(FP), DI
    MOVQ    y+16(FP), SI

    // Used later to calculate a mask
    XORQ    CX, CX

    // [R8-R14]: z = x + y
    MOVQ    ( 0)(DI), R8;   ADDQ    ( 0)(SI), R8
    MOVQ    ( 8)(DI), R9;   ADCQ    ( 8)(SI), R9
    MOVQ    (16)(DI), R10;  ADCQ    (16)(SI), R10
    MOVQ    (24)(DI), R11;  ADCQ    (24)(SI), R11
    MOVQ    (32)(DI), R12;  ADCQ    (32)(SI), R12
    MOVQ    (40)(DI), R13;  ADCQ    (40)(SI), R13
    MOVQ    (48)(DI), R14;  ADCQ    (48)(SI), R14

    XORQ    DI, DI

    MOVQ    P434X2_0, AX;   SUBQ    AX, R8
    MOVQ    P434X2_1, AX;   SBBQ    AX, R9
                            SBBQ    AX, R10
    MOVQ    P434X2_3, AX;   SBBQ    AX, R11
    MOVQ    P434X2_4, AX;   SBBQ    AX, R12
    MOVQ    P434X2_5, AX;   SBBQ    AX, R13
    MOVQ    P434X2_6, AX;   SBBQ    AX, R14

    // mask
    SBBQ    $0, CX

    // if z<0 add P434x2 back
    MOVQ    P434X2_0, R15;  ANDQ    CX, R15;
    MOVQ    P434X2_1, AX;   ANDQ    CX, AX;

    ADDQ    R8, R15; MOVQ  R15, ( 0)(DX)
    ADCQ    AX, R9;  MOVQ   R9, ( 8)(DX)
    ADCQ    AX, R10; MOVQ  R10, (16)(DX)

    ADCQ    $0, DI
    MOVQ    P434X2_3, R15;  ANDQ    CX, R15;
    MOVQ    P434X2_4,  R8;  ANDQ    CX, R8;
    MOVQ    P434X2_5,  R9;  ANDQ    CX, R9;
    MOVQ    P434X2_6, R10;  ANDQ    CX, R10;
    BTQ     $0, DI

    ADCQ    R11, R15;   MOVQ R15, (24)(DX)
    ADCQ    R12, R8;    MOVQ R8,  (32)(DX)
    ADCQ    R13, R9;    MOVQ R9,  (40)(DX)
    ADCQ    R14, R10;   MOVQ R10, (48)(DX)

    RET

TEXT ·adlP434(SB),NOSPLIT,$0-24
    MOVQ    z+0(FP), DX
    MOVQ    x+8(FP), DI
    MOVQ    y+16(FP),SI

    MOVQ    ( 0)(DI), R8
    ADDQ    ( 0)(SI), R8
    MOVQ    ( 8)(DI), R9
    ADCQ    ( 8)(SI), R9
    MOVQ    (16)(DI), R10
    ADCQ    (16)(SI), R10
    MOVQ    (24)(DI), R11
    ADCQ    (24)(SI), R11
    MOVQ    (32)(DI), R12
    ADCQ    (32)(SI), R12
    MOVQ    (40)(DI), R13
    ADCQ    (40)(SI), R13
    MOVQ    (48)(DI), R14
    ADCQ    (48)(SI), R14
    MOVQ    (56)(DI), R15
    ADCQ    (56)(SI), R15
    MOVQ    (64)(DI), AX
    ADCQ    (64)(SI), AX
    MOVQ    (72)(DI), BX
    ADCQ    (72)(SI), BX
    MOVQ    (80)(DI), CX
    ADCQ    (80)(SI), CX

    MOVQ    R8, ( 0)(DX)
    MOVQ    R9, ( 8)(DX)
    MOVQ    R10,(16)(DX)
    MOVQ    R11,(24)(DX)
    MOVQ    R12,(32)(DX)
    MOVQ    R13,(40)(DX)
    MOVQ    R14,(48)(DX)
    MOVQ    R15,(56)(DX)
    MOVQ    AX, (64)(DX)
    MOVQ    BX, (72)(DX)
    MOVQ    CX, (80)(DX)

    MOVQ    (88)(DI), R8
    ADCQ    (88)(SI), R8
    MOVQ    (96)(DI), R9
    ADCQ    (96)(SI), R9
    MOVQ    (104)(DI), R10
    ADCQ    (104)(SI), R10

    MOVQ    R8, (88)(DX)
    MOVQ    R9, (96)(DX)
    MOVQ    R10,(104)(DX)
    RET

TEXT ·subP434(SB),NOSPLIT,$0-24
    MOVQ    z+0(FP), DX
    MOVQ    x+8(FP), DI
    MOVQ    y+16(FP), SI

    // Used later to calculate a mask
    XORQ    CX, CX

    MOVQ    ( 0)(DI), R8;  SUBQ    ( 0)(SI), R8
    MOVQ    ( 8)(DI), R9;  SBBQ    ( 8)(SI), R9
    MOVQ    (16)(DI), R10; SBBQ    (16)(SI), R10
    MOVQ    (24)(DI), R11; SBBQ    (24)(SI), R11
    MOVQ    (32)(DI), R12; SBBQ    (32)(SI), R12
    MOVQ    (40)(DI), R13; SBBQ    (40)(SI), R13
    MOVQ    (48)(DI), R14; SBBQ    (48)(SI), R14

    // mask
    SBBQ    $0, CX
    XORQ    R15, R15

    // if z<0 add p434x2 back
    MOVQ    P434X2_0, DI; ANDQ    CX, DI
    MOVQ    P434X2_1, SI; ANDQ    CX, SI
    MOVQ    P434X2_3, AX; ANDQ    CX, AX

    ADDQ     DI, R8;  MOVQ     R8, ( 0)(DX)
    ADCQ     SI, R9;  MOVQ     R9, ( 8)(DX)
    ADCQ     SI, R10; MOVQ    R10, (16)(DX)
    ADCQ     AX, R11; MOVQ    R11, (24)(DX)
    ADCQ    $0, R15

    MOVQ    P434X2_4, R8;  ANDQ    CX, R8;
    MOVQ    P434X2_5, R9;  ANDQ    CX, R9;
    MOVQ    P434X2_6, R10; ANDQ    CX, R10

    BTQ     $0, R15

    ADCQ     R8, R12; MOVQ    R12, (32)(DX)
    ADCQ     R9, R13; MOVQ    R13, (40)(DX)
    ADCQ    R10, R14; MOVQ    R14, (48)(DX)
    RET

TEXT ·sulP434(SB),NOSPLIT,$0-24
    MOVQ z+0(FP), DX
    MOVQ x+8(FP), DI
    MOVQ y+16(FP), SI

    // Used later to store result of 0-borrow
    XORQ CX, CX

    // SUBC for first 10 limbs
    MOVQ    ( 0)(DI), R8;  SUBQ    ( 0)(SI), R8
    MOVQ    ( 8)(DI), R9;  SBBQ    ( 8)(SI), R9
    MOVQ    (16)(DI), R10; SBBQ    (16)(SI), R10
    MOVQ    (24)(DI), R11; SBBQ    (24)(SI), R11
    MOVQ    (32)(DI), R12; SBBQ    (32)(SI), R12
    MOVQ    (40)(DI), R13; SBBQ    (40)(SI), R13
    MOVQ    (48)(DI), R14; SBBQ    (48)(SI), R14
    MOVQ    (56)(DI), R15; SBBQ    (56)(SI), R15
    MOVQ    (64)(DI), AX;  SBBQ    (64)(SI), AX
    MOVQ    (72)(DI), BX;  SBBQ    (72)(SI), BX

    MOVQ     R8, ( 0)(DX)
    MOVQ     R9, ( 8)(DX)
    MOVQ    R10, (16)(DX)
    MOVQ    R11, (24)(DX)
    MOVQ    R12, (32)(DX)
    MOVQ    R13, (40)(DX)
    MOVQ    R14, (48)(DX)
    MOVQ    R15, (56)(DX)
    MOVQ     AX, (64)(DX)
    MOVQ     BX, (72)(DX)

    // SUBC for last 4 limbs
    MOVQ    ( 80)(DI), R8;  SBBQ    ( 80)(SI), R8
    MOVQ    ( 88)(DI), R9;  SBBQ    ( 88)(SI), R9
    MOVQ    ( 96)(DI), R10; SBBQ    ( 96)(SI), R10
    MOVQ    (104)(DI), R11; SBBQ    (104)(SI), R11

    // Store carry flag
    SBBQ    $0, CX

    MOVQ    R8,  ( 80)(DX)
    MOVQ    R9,  ( 88)(DX)
    MOVQ    R10, ( 96)(DX)
    MOVQ    R11, (104)(DX)

    // Load p into registers:
    MOVQ    P434_0, R8;  ANDQ    CX, R8
    // P434_{1,2} = P434_0, so reuse R8
    MOVQ    P434_3, R9;  ANDQ    CX, R9
    MOVQ    P434_4, R10; ANDQ    CX, R10
    MOVQ    P434_5, R11; ANDQ    CX, R11
    MOVQ    P434_6, R12; ANDQ    CX, R12

    MOVQ   (56   )(DX), AX; ADDQ R8,  AX; MOVQ AX, (56   )(DX)
    MOVQ   (56+ 8)(DX), AX; ADCQ R8,  AX; MOVQ AX, (56+ 8)(DX)
    MOVQ   (56+16)(DX), AX; ADCQ R8,  AX; MOVQ AX, (56+16)(DX)
    MOVQ   (56+24)(DX), AX; ADCQ R9,  AX; MOVQ AX, (56+24)(DX)
    MOVQ   (56+32)(DX), AX; ADCQ R10, AX; MOVQ AX, (56+32)(DX)
    MOVQ   (56+40)(DX), AX; ADCQ R11, AX; MOVQ AX, (56+40)(DX)
    MOVQ   (56+48)(DX), AX; ADCQ R12, AX; MOVQ AX, (56+48)(DX)

    RET

TEXT ·modP434(SB),NOSPLIT,$0-8
    MOVQ    x+0(FP), DI

    // Zero AX for later use:
    XORQ    AX, AX

    // Set x <- x - p
    MOVQ    P434_0, R8
    SUBQ    R8,  ( 0)(DI)
    // P434_{1,2} = P434_0, so reuse R8
    MOVQ    P434_3, R9
    SBBQ    R8,  ( 8)(DI)
    SBBQ    R8,  (16)(DI)
    MOVQ    P434_4, R10
    SBBQ    R9,  (24)(DI)
    MOVQ    P434_5, R11
    SBBQ    R10, (32)(DI)
    MOVQ    P434_6, R12
    SBBQ    R11, (40)(DI)
    SBBQ    R12, (48)(DI)

    // save carry
    SBBQ    $0, AX

    // Conditionally add p to x if x-p < 0
    ANDQ    AX, R8
    ANDQ    AX, R9
    ANDQ    AX, R10
    ANDQ    AX, R11
    ANDQ    AX, R12

    ADDQ    R8, ( 0)(DI)
    ADCQ    R8, ( 8)(DI)
    ADCQ    R8, (16)(DI)
    ADCQ    R9, (24)(DI)
    ADCQ    R10,(32)(DI)
    ADCQ    R11,(40)(DI)
    ADCQ    R12,(48)(DI)
    RET

// 434-bit multiplication using Karatsuba (one level),
// schoolbook (one level).
TEXT ·mulP434(SB),NOSPLIT,$112-24
    MOVQ    z+0(FP), CX
    MOVQ    x+8(FP), DI
    MOVQ    y+16(FP), SI

    // Check whether to use optimized implementation
    CMPB    ·HasADXandBMI2(SB), $1
    JE      mul_with_mulx_adcx_adox

    // rcx[0-3] <- AH+AL
    XORQ         AX, AX
    MOVQ   0x20(DI), R8
    MOVQ   0x28(DI), R9
    MOVQ   0x30(DI), R10
    XORQ        R11, R11
    ADDQ    0x0(DI), R8
    ADCQ    0x8(DI), R9
    ADCQ   0x10(DI), R10
    ADCQ   0x18(DI), R11
    // store AH+AL mask
    SBBQ   $0, AX
    MOVQ   AX, 0x40(SP)
    // store AH+AL in 0-0x18(rcx)
    MOVQ    R8,  0x0(CX)
    MOVQ    R9,  0x8(CX)
    MOVQ   R10, 0x10(CX)
    MOVQ   R11, 0x18(CX)

    // r12-r15 <- BH+BL
    XORQ         DX, DX
    MOVQ   0x20(SI), R12
    MOVQ   0x28(SI), R13
    MOVQ   0x30(SI), R14
    XORQ        R15, R15
    ADDQ    0x0(SI), R12
    ADCQ    0x8(SI), R13
    ADCQ   0x10(SI), R14
    ADCQ   0x18(SI), R15
    SBBQ         $0, DX

    // store BH+BL mask
    MOVQ DX, 0x48(SP)

    // (rsp[0-0x38]) <- (AH+AL)*(BH+BL)
    MOVQ   (CX), AX
    MULQ   R12
    MOVQ   AX, (SP)
    MOVQ   DX, R8

    XORQ    R9, R9
    MOVQ   (CX), AX
    MULQ    R13
    ADDQ     AX, R8
    ADCQ     DX, R9

    XORQ   R10, R10
    MOVQ   0x8(CX), AX
    MULQ   R12
    ADDQ    AX, R8
    MOVQ    R8,  0x8(SP)
    ADCQ    DX, R9
    ADCQ    $0, R10

    XORQ   R8, R8
    MOVQ   (CX), AX
    MULQ   R14
    ADDQ   AX, R9
    ADCQ   DX, R10
    ADCQ   $0, R8

    MOVQ   0x10(CX), AX
    MULQ   R12
    ADDQ   AX, R9
    ADCQ   DX, R10
    ADCQ   $0, R8

    MOVQ   0x8(CX), AX
    MULQ   R13
    ADDQ   AX, R9
    MOVQ   R9, 0x10(SP)
    ADCQ   DX, R10
    ADCQ   $0, R8

    XORQ   R9, R9
    MOVQ   (CX),AX
    MULQ   R15
    ADDQ   AX, R10
    ADCQ   DX, R8
    ADCQ   $0, R9

    MOVQ   0x18(CX), AX
    MULQ   R12
    ADDQ   AX, R10
    ADCQ   DX, R8
    ADCQ   $0, R9

    MOVQ   0x8(CX), AX
    MULQ   R14
    ADDQ   AX, R10
    ADCQ   DX, R8
    ADCQ   $0, R9

    MOVQ   0x10(CX), AX
    MULQ   R13
    ADDQ    AX, R10
    MOVQ   R10, 0x18(SP)
    ADCQ    DX, R8
    ADCQ    $0, R9

    XORQ   R10, R10
    MOVQ   0x8(CX), AX
    MULQ   R15
    ADDQ    AX, R8
    ADCQ    DX, R9
    ADCQ    $0, R10

    MOVQ   0x18(CX), AX
    MULQ   R13
    ADDQ   AX, R8
    ADCQ   DX, R9
    ADCQ   $0, R10

    MOVQ   0x10(CX), AX
    MULQ   R14
    ADDQ    AX, R8
    MOVQ    R8, 0x20(SP)
    ADCQ    DX, R9
    ADCQ    $0, R10

    XORQ   R11, R11
    MOVQ   0x10(CX), AX
    MULQ   R15
    ADDQ    AX, R9
    ADCQ    DX, R10
    ADCQ    $0, R11

    MOVQ   0x18(CX), AX
    MULQ   R14
    ADDQ    AX, R9
    MOVQ    R9, 0x28(SP)
    ADCQ    DX, R10
    ADCQ    $0, R11

    MOVQ   0x18(CX), AX
    MULQ   R15
    ADDQ    AX, R10
    MOVQ   R10, 0x30(SP)
    ADCQ    DX, R11
    MOVQ    R11,0x38(SP)

    // r12-r15 <- masked (BH + BL)
    MOVQ   0x40(SP), AX
    ANDQ   AX, R12
    ANDQ   AX, R13
    ANDQ   AX, R14
    ANDQ   AX, R15

    // r8-r11 <- masked (AH + AL)
    MOVQ   0x48(SP), AX
    MOVQ   0x00(CX), R8
    ANDQ         AX, R8
    MOVQ   0x08(CX), R9
    ANDQ         AX, R9
    MOVQ   0x10(CX), R10
    ANDQ         AX, R10
    MOVQ   0x18(CX), R11
    ANDQ         AX, R11

    // r12-r15 <- masked (AH + AL) + masked (BH + BL)
    ADDQ    R8, R12
    ADCQ    R9, R13
    ADCQ   R10, R14
    ADCQ   R11, R15

    // rsp[0x20-0x38] <- (AH+AL) x (BH+BL) high
    MOVQ   0x20(SP), AX
    ADDQ         AX, R12
    MOVQ   0x28(SP), AX
    ADCQ         AX, R13
    MOVQ   0x30(SP), AX
    ADCQ         AX, R14
    MOVQ   0x38(SP), AX
    ADCQ         AX, R15
    MOVQ   R12, 0x50(SP)
    MOVQ   R13, 0x58(SP)
    MOVQ   R14, 0x60(SP)
    MOVQ   R15, 0x68(SP)

    // [rcx] <- CL = AL x BL
    MOVQ   (DI), R11
    MOVQ   (SI), AX
    MULQ    R11
    XORQ    R9,  R9
    MOVQ    AX, (CX)
    MOVQ    DX, R8

    MOVQ   0x10(DI), R14
    MOVQ   0x8(SI), AX
    MULQ   R11
    XORQ   R10, R10
    ADDQ    AX, R8
    ADCQ    DX, R9

    MOVQ   0x8(DI), R12
    MOVQ   (SI), AX
    MULQ   R12
    ADDQ   AX, R8
    MOVQ   R8, 0x8(CX)
    ADCQ   DX, R9
    ADCQ   $0, R10

    XORQ   R8,  R8
    MOVQ   0x10(SI), AX
    MULQ   R11
    ADDQ   AX, R9
    ADCQ   DX, R10
    ADCQ   $0, R8

    MOVQ   (SI), R13
    MOVQ   R14, AX
    MULQ   R13
    ADDQ    AX, R9
    ADCQ    DX, R10
    ADCQ    $0, R8

    MOVQ   0x8(SI), AX
    MULQ   R12
    ADDQ   AX, R9
    MOVQ   R9, 0x10(CX)
    ADCQ   DX, R10
    ADCQ   $0, R8

    XORQ   R9,  R9
    MOVQ   0x18(SI), AX
    MULQ   R11
    MOVQ   0x18(DI), R15
    ADDQ   AX, R10
    ADCQ   DX, R8
    ADCQ   $0, R9

    MOVQ   R15, AX
    MULQ   R13
    ADDQ   AX, R10
    ADCQ   DX, R8
    ADCQ   $0, R9

    MOVQ   0x10(SI), AX
    MULQ   R12
    ADDQ   AX, R10
    ADCQ   DX, R8
    ADCQ   $0, R9

    MOVQ   0x8(SI), AX
    MULQ   R14
    ADDQ    AX, R10
    MOVQ   R10, 0x18(CX)
    ADCQ    DX, R8
    ADCQ    $0, R9

    XORQ   R10, R10
    MOVQ   0x18(SI), AX
    MULQ   R12
    ADDQ    AX, R8
    ADCQ    DX, R9
    ADCQ    $0, R10

    MOVQ   0x8(SI), AX
    MULQ   R15
    ADDQ    AX, R8
    ADCQ    DX, R9
    ADCQ    $0, R10

    MOVQ   0x10(SI), AX
    MULQ   R14
    ADDQ    AX, R8
    MOVQ    R8,  0x20(CX)
    ADCQ    DX, R9
    ADCQ    $0, R10

    XORQ   R8, R8
    MOVQ   0x18(SI), AX
    MULQ   R14
    ADDQ    AX, R9
    ADCQ    DX, R10
    ADCQ    $0, R8

    MOVQ   0x10(SI), AX
    MULQ   R15
    ADDQ    AX, R9
    MOVQ    R9,  0x28(CX)
    ADCQ    DX, R10
    ADCQ    $0, R8

    MOVQ   0x18(SI), AX
    MULQ   R15
    ADDQ    AX, R10
    MOVQ   R10, 0x30(CX)
    ADCQ    DX, R8
    MOVQ    R8, 0x38(CX)

    // rcx[0x40-0x68] <- AH*BH
    // multiplies 2 192-bit numbers A,B
    MOVQ   0x20(DI), R11
    MOVQ   0x20(SI), AX
    MULQ   R11
    XORQ    R9,  R9
    MOVQ    AX, 0x40(CX)
    MOVQ    DX, R8

    MOVQ   0x30(DI), R14
    MOVQ   0x28(SI), AX
    MULQ   R11
    XORQ   R10, R10
    ADDQ    AX, R8
    ADCQ    DX, R9

    MOVQ   0x28(DI), R12
    MOVQ   0x20(SI), AX
    MULQ   R12
    ADDQ    AX, R8
    MOVQ    R8,  0x48(CX)
    ADCQ    DX, R9
    ADCQ    $0, R10

    XORQ   R8,  R8
    MOVQ   0x30(SI), AX
    MULQ   R11
    ADDQ    AX, R9
    ADCQ    DX, R10
    ADCQ    $0, R8

    MOVQ   0x20(SI), R13
    MOVQ   R14, AX
    MULQ   R13
    ADDQ    AX, R9
    ADCQ    DX, R10
    ADCQ    $0, R8

    MOVQ   0x28(SI), AX
    MULQ   R12
    ADDQ    AX, R9
    MOVQ    R9,  0x50(CX)
    ADCQ    DX, R10
    ADCQ    $0, R8

    MOVQ   0x30(SI), AX
    MULQ   R12
    XORQ   R12, R12
    ADDQ    AX, R10
    ADCQ    DX, R8
    ADCQ    $0, R12

    MOVQ   0x28(SI), AX
    MULQ   R14
    ADDQ    AX, R10
    ADCQ    DX, R8
    ADCQ    $0, R12
    MOVQ   R10, 0x58(CX)

    MOVQ    0x30(SI), AX
    MULQ    R14
    ADDQ     AX, R8
    ADCQ     $0, R12
    MOVQ     R8,  0x60(CX)

    ADDQ    R12, DX

    // [r8-r15] <- (AH+AL)x(BH+BL) - ALxBL
    MOVQ    0x0(SP), R8
    SUBQ    0x0(CX), R8
    MOVQ    0x8(SP), R9
    SBBQ    0x8(CX), R9
    MOVQ   0x10(SP), R10
    SBBQ   0x10(CX), R10
    MOVQ   0x18(SP), R11
    SBBQ   0x18(CX), R11
    MOVQ   0x50(SP), R12
    SBBQ   0x20(CX), R12
    MOVQ   0x58(SP), R13
    SBBQ   0x28(CX), R13
    MOVQ   0x60(SP), R14
    SBBQ   0x30(CX), R14
    MOVQ   0x68(SP), R15
    SBBQ   0x38(CX), R15

    // [r8-r15] <- (AH+AL) x (BH+BL) - ALxBL - AHxBH
    MOVQ   0x40(CX), AX
    SUBQ   AX, R8
    MOVQ   0x48(CX), AX
    SBBQ   AX, R9
    MOVQ   0x50(CX), AX
    SBBQ   AX, R10
    MOVQ   0x58(CX), AX
    SBBQ   AX, R11
    MOVQ   0x60(CX), AX
    SBBQ   AX, R12
    SBBQ   DX, R13
    SBBQ   $0, R14
    SBBQ   $0, R15

    // Final result
    ADDQ   0x20(CX), R8
    MOVQ    R8, 0x20(CX)    // OUT4
    ADCQ   0x28(CX), R9
    MOVQ    R9, 0x28(CX)    // OUT5
    ADCQ   0x30(CX), R10
    MOVQ   R10, 0x30(CX)    // OUT6
    ADCQ   0x38(CX), R11
    MOVQ   R11, 0x38(CX)    // OUT7
    ADCQ   0x40(CX), R12
    MOVQ   R12, 0x40(CX)    // OUT8
    ADCQ   0x48(CX), R13
    MOVQ   R13, 0x48(CX)    // OUT9
    ADCQ   0x50(CX), R14
    MOVQ   R14, 0x50(CX)    // OUT10
    ADCQ   0x58(CX), R15
    MOVQ   R15, 0x58(CX)    // OUT11
    MOVQ   0x60(CX), R12
    ADCQ    $0, R12
    MOVQ   R12, 0x60(CX)    // OUT12
    ADCQ    $0, DX
    MOVQ    DX, 0x68(CX)    // OUT13
    RET

mul_with_mulx_adcx_adox:
    // Mul implementation for CPUs supporting two independent carry chain
    // (ADOX/ADCX) instructions and carry-less MULX multiplier
    XORQ    AX, AX
    MOVQ    0x0(DI), R8
    MOVQ    0x8(DI), R9
    MOVQ   0x10(DI), R10
    MOVQ   0x18(DI), R11

    MOVQ   BP, 0x70(SP) // push: BP is Callee-save.

    ADDQ   0x20(DI), R8
    ADCQ   0x28(DI), R9
    ADCQ   0x30(DI), R10
    ADCQ     $0, R11
    SBBQ     $0, AX
    MOVQ   R8,   0x0(SP)
    MOVQ   R9,   0x8(SP)
    MOVQ   R10, 0x10(SP)
    MOVQ   R11, 0x18(SP)

    // r12-r15 <- BH + BL, rbx <- mask
    XORQ         BX, BX
    MOVQ    0x0(SI), R12
    MOVQ    0x8(SI), R13
    MOVQ   0x10(SI), R14
    MOVQ   0x18(SI), R15
    ADDQ   0x20(SI), R12
    ADCQ   0x28(SI), R13
    ADCQ   0x30(SI), R14
    ADCQ    $0, R15
    SBBQ    $0, BX
    MOVQ   R12, 0x20(SP)
    MOVQ   R13, 0x28(SP)
    MOVQ   R14, 0x30(SP)
    MOVQ   R15, 0x38(SP)

    // r12-r15 <- masked (BH + BL)
    ANDQ   AX, R12
    ANDQ   AX, R13
    ANDQ   AX, R14
    ANDQ   AX, R15

    // r8-r11 <- masked (AH + AL)
    ANDQ   BX, R8
    ANDQ   BX, R9
    ANDQ   BX, R10
    ANDQ   BX, R11

    // r8-r11 <- masked (AH + AL) + masked (BH + BL)
    ADDQ   R12, R8
    ADCQ   R13, R9
    ADCQ   R14, R10
    ADCQ   R15, R11
    MOVQ    R8, 0x40(SP)
    MOVQ    R9, 0x48(SP)
    MOVQ   R10, 0x50(SP)
    MOVQ   R11, 0x58(SP)

    // [rsp] <- CM = (AH+AL) x (BH+BL)
    MULX256(0,SP,32,SP,0,SP,R8,R9,R10,R11,R12,R13,R14,R15,BX,BP)
    // [rcx] <- CL = AL x BL (Result c0-c3)
    MULX256(0,DI,0,SI,0,CX,R8,R9,R10,R11,R12,R13,R14,R15,BX,BP)
    // [rcx+64], rbx, rbp, rax <- CH = AH x BH
    MULX192(32,DI,32,SI,64,CX,R8,BX,R10,BP,R12,R13,R14)

    // r8-r11 <- (AH+AL) x (BH+BL), final step
    MOVQ   0x40(SP),  R8
    MOVQ   0x48(SP),  R9
    MOVQ   0x50(SP), R10
    MOVQ   0x58(SP), R11

    MOVQ   0x20(SP), DX
    ADDQ   DX, R8
    MOVQ   0x28(SP), DX
    ADCQ   DX, R9
    MOVQ   0x30(SP), DX
    ADCQ   DX, R10
    MOVQ   0x38(SP), DX
    ADCQ   DX, R11

    // [rsp], x3-x5 <- (AH+AL) x (BH+BL) - ALxBL
    MOVQ    0x0(SP), R12
    MOVQ    0x8(SP), R13
    MOVQ   0x10(SP), R14
    MOVQ   0x18(SP), R15
    SUBQ    0x0(CX), R12
    SBBQ    0x8(CX), R13
    SBBQ   0x10(CX), R14
    SBBQ   0x18(CX), R15
    SBBQ   0x20(CX), R8
    SBBQ   0x28(CX), R9
    SBBQ   0x30(CX), R10
    SBBQ   0x38(CX), R11

    // r8-r15 <- (AH+AL) x (BH+BL) - ALxBL - AHxBH
    SUBQ   0x40(CX), R12
    SBBQ   0x48(CX), R13
    SBBQ   0x50(CX), R14
    SBBQ   BX, R15
    SBBQ   BP, R8
    SBBQ   AX, R9
    SBBQ   $0, R10
    SBBQ   $0, R11

    ADDQ   0x20(CX), R12
    MOVQ   R12, 0x20(CX)    // OUT4
    ADCQ   0x28(CX), R13
    MOVQ   R13, 0x28(CX)    // OUT5
    ADCQ   0x30(CX), R14
    MOVQ   R14, 0x30(CX)    // OUT6
    ADCQ   0x38(CX), R15
    MOVQ   R15, 0x38(CX)    // OUT7
    ADCQ   0x40(CX), R8
    MOVQ   R8, 0x40(CX)     // OUT8
    ADCQ   0x48(CX), R9
    MOVQ   R9, 0x48(CX)     // OUT9
    ADCQ   0x50(CX), R10
    MOVQ   R10, 0x50(CX)    // OUT10
    ADCQ   BX, R11
    MOVQ   R11, 0x58(CX)    // OUT11
    ADCQ   $0, BP
    MOVQ   BP, 0x60(CX)    // OUT12
    ADCQ   $0, AX
    MOVQ   AX, 0x68(CX)    // OUT13

    MOVQ   0x70(SP), BP // pop: BP is Callee-save.
    RET

TEXT ·rdcP434(SB),$0-16
    MOVQ    z+0(FP), SI
    MOVQ    x+8(FP), DI
    CMPB    ·HasADXandBMI2(SB), $1
    JE      redc_bdw
#define MUL01 MUL128x256( 0,DI,·P434p1+(8*P434_P1_ZEROS),R8,R9,R10,R11,R12,R13,R14,CX)
#define MUL23 MUL128x256(16,DI,·P434p1+(8*P434_P1_ZEROS),R8,R9,R10,R11,R12,R13,R14,CX)
#define MUL45 MUL128x256(32,DI,·P434p1+(8*P434_P1_ZEROS),R8,R9,R10,R11,R12,R13,R14,CX)
#define MUL67  MUL64x256(48,DI,·P434p1+(8*P434_P1_ZEROS),R8,R9,R10,R11,R12,R13)
    REDC_MULQ(MUL01, MUL23, MUL45, MUL67)
#undef MUL01
#undef MUL23
#undef MUL45
#undef MUL67
    RET

// 434-bit montgomery reduction Uses MULX/ADOX/ADCX instructions
// available on Broadwell micro-architectures and newer.
redc_bdw:
#define MULX01 MULX128x256(R14,·P434p1+(8*P434_P1_ZEROS),R9 ,R10,R11,R12,R13)
#define MULX23 MULX128x256(R8 ,·P434p1+(8*P434_P1_ZEROS),BP ,R12,R13,R14,CX )
#define MULX45 MULX128x256(BX ,·P434p1+(8*P434_P1_ZEROS),R9 ,R10,BP ,R12,R13)
#define MULX67 MULX64x256 (    ·P434p1+(8*P434_P1_ZEROS),BX ,R8 ,R9 ,R11,CX )
    REDC_MULX(·P434p1+(8*P434_P1_ZEROS)+0(SB), MULX01, MULX23, MULX45, MULX67)
#undef MULX01
#undef MULX23
#undef MULX45
#undef MULX67
    RET
