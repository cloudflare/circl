// @author Armando Faz

// +build amd64

#include "fp448_amd64.h"

// func CSelect(x, y *Element, b int)
TEXT ·CSelect(SB),NOSPLIT,$0
    MOVQ x+0(FP), DI
    MOVQ y+8(FP), SI
    MOVQ b+16(FP), BX
    cselect(0(DI),0(SI),BX)
    RET

// func CSwap(x, y *Element, b int)
TEXT ·CSwap(SB),NOSPLIT,$0
    MOVQ x+0(FP), DI
    MOVQ y+8(FP), SI
    MOVQ b+16(FP), BX
    cswap(0(DI),0(SI),BX)
    RET

// func Add(z, x *Element)
TEXT ·AddSub(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
	addSub(0(DI),0(SI))
    RET
	
// func addLeg(z,x,y *Element)
TEXT ·addLeg(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    addition(0(DI),0(SI),0(BX))
    RET

// func addAdx(z,x,y *Element)
TEXT ·addAdx(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    additionAdx(0(DI),0(SI),0(BX))
    RET

// func Sub(z,x,y *Element)
TEXT ·Sub(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    subtraction(0(DI),0(SI),0(BX))
    RET

// func mulA24(z, x *Element)
TEXT ·mulA24(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    multiplyA24(0(DI),0(SI))
    RET

// func mulA24Adx(z, x *Element)
TEXT ·mulA24Adx(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    multiplyA24Adx(0(DI),0(SI))
    RET

// func intMul(z*[2*SizeField]byte, x, y *Element)
TEXT ·intMul(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    integerMul(0(DI),0(SI),0(BX))
    RET

// func intMulAdx(z*[2*SizeField]byte, x, y *Element)
TEXT ·intMulAdx(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    integerMulAdx(0(DI),0(SI),0(BX))
    RET

// func intSqr(z*[2*SizeField]byte, x *Element)
TEXT ·intSqr(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    integerSqr(0(DI),0(SI))
    RET

// func intSqrAdx(z*[2*SizeField]byte, x *Element)
TEXT ·intSqrAdx(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    integerSqrAdx(0(DI),0(SI))
    RET

// func reduce(z *Element, x *[2 * SizeField]byte)
TEXT ·reduce(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    reduceFromDouble(0(DI),0(SI))
    RET

// func reduceAdx(z *Element, x *[2 * SizeField]byte)
TEXT ·reduceAdx(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    reduceFromDoubleAdx(0(DI),0(SI))
    RET

// func sqrn(z *Element, buffer *[2 * SizeField]byte, times uint)
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

// func sqrnAdx(z *Element, buffer *[2 * SizeField]byte, times uint)
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
