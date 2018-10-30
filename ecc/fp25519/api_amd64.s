// @author Armando Faz

// +build amd64

#include "fp25519_amd64.h"

// func CSelect(x, y *Element, b int)
TEXT ·CSelect(SB),NOSPLIT,$0
    MOVQ x+0(FP), DI
    MOVQ y+8(FP), SI
    MOVQ b+16(FP), BX
    cselect(0(DI),0(SI),BX)
    RET
// end of CSelect

// func CSwap(x, y *Element, b int)
TEXT ·CSwap(SB),NOSPLIT,$0
    MOVQ x+0(FP), DI
    MOVQ y+8(FP), SI
    MOVQ b+16(FP), BX
    cswap(0(DI),0(SI),BX)
    RET
// end of CSwap

// func AddSub(z, x *Element)
TEXT ·AddSub(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
	addSub(0(DI),0(SI))
    RET
// end of AddSub

// func addLeg(z,x,y *Element)
TEXT ·addLeg(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    addition(0(DI),0(SI),0(BX))
    RET
// end of addLeg

// func addAdx(z,x,y *Element)
TEXT ·addAdx(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    additionAdx(0(DI),0(SI),0(BX))
    RET
// end of addAdx

// func Sub(z,x,y *Element)
TEXT ·Sub(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    subtraction(0(DI),0(SI),0(BX))
    RET
// end of Sub

// func mulA24(z, x *Element)
TEXT ·mulA24(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    multiplyA24(0(DI),0(SI))
    RET
// end of mulA24

// func mulA24Adx(z, x *Element)
TEXT ·mulA24Adx(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    multiplyA24Adx(0(DI),0(SI))
    RET
// end of mulA24Adx

// func intMul(z*[2*SizeElement]byte, x, y *Element)
TEXT ·intMul(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    integerMul(0(DI),0(SI),0(BX))
    RET
// end of intMul

// func intMulAdx(z*[2*SizeElement]byte, x, y *Element)
TEXT ·intMulAdx(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    integerMulAdx(0(DI),0(SI),0(BX))
    RET
// end of intMulAdx

// func intSqr(z*[2*SizeElement]byte, x *Element)
TEXT ·intSqr(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    integerSqr(0(DI),0(SI))
    RET
// end of intSqr

// func intSqrAdx(z*[2*SizeElement]byte, x *Element)
TEXT ·intSqrAdx(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    integerSqrAdx(0(DI),0(SI))
    RET
// end of intSqrAdx

// func reduce(z *Element, x *[2 * SizeElement]byte)
TEXT ·reduce(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    reduceFromDouble(0(DI),0(SI))
    RET
// end of reduce

// func reduceAdx(z *Element, x *[2 * SizeElement]byte)
TEXT ·reduceAdx(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    reduceFromDoubleAdx(0(DI),0(SI))
    RET
// end of reduceAdx

// func sqrn(z *Element, buffer *[2 * SizeElement]byte, times uint)
TEXT ·sqrn(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ buffer+8(FP), SI
    MOVQ times+16(FP),BX
L0:
    CMPQ BX, $0
    JZ L1
    integerSqr(0(SI),0(DI))
    reduceFromDouble(0(DI),0(SI))
    DECQ BX
    JMP L0
L1:
    RET
// end of sqrn

// func sqrnAdx(z *Element, buffer *[2 * SizeElement]byte, times uint)
TEXT ·sqrnAdx(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ buffer+8(FP), SI
    MOVQ times+16(FP),BX
    L0:
    CMPQ BX, $0
    JZ L1
    integerSqrAdx(0(SI),0(DI))
    reduceFromDoubleAdx(0(DI),0(SI))
    DECQ BX
    JMP L0
    L1:
    RET
// end of sqrnAdx

// func ModuloP(z *Element)
TEXT ·ModuloP(SB),NOSPLIT,$0
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
// end of ModuloP
