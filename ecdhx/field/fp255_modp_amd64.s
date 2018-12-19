#include "textflag.h"

// +build amd64

// func moduloP255(z *Element255)
TEXT ·moduloP255(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI;

    MOVQ   (DI),  R8;
    MOVQ  8(DI),  R9;
    MOVQ 16(DI), R10;
    MOVQ 24(DI), R11;

    MOVL $19, AX;
    MOVL $38, CX;

    BTRQ $63, R11; // PUT BIT 255 IN CARRY FLAG AND CLEAR
    CMOVLCC AX, CX; // C[255] ? 38 : 19

    // ADD EITHER 19 OR 38 TO C
    ADDQ CX,  R8;
    ADCQ $0,  R9;
    ADCQ $0, R10;
    ADCQ $0, R11;

    // TEST FOR BIT 255 AGAIN; ONLY TRIGGERED ON OVERFLOW MODULO 2^255-19
    MOVL     $0,  CX;
    CMOVLPL  AX,  CX; // C[255] ? 0 : 19
    BTRQ    $63, R11; // CLEAR BIT 255

    // SUBTRACT 19 IF NECESSARY
    SUBQ CX,  R8; MOVQ  R8,   (DI);
    SBBQ $0,  R9; MOVQ  R9,  8(DI);
    SBBQ $0, R10; MOVQ R10, 16(DI);
    SBBQ $0, R11; MOVQ R11, 24(DI);
    RET
