#include "field.h"

// func pDbl(a *point)
TEXT ·pDbl(SB),0,$128-8
	MOVQ a+0(FP), DI

	feSquare( 0(DI),  0(SP)) // A = X1^2
	feSquare(32(DI), 32(SP)) // B = Y1^2

	// D = -(A + B)
	// G = B - A
	feMov( 0(SP), 8(SP),16(SP),24(SP), AX,BX, CX, DX)
	feMov(32(SP),40(SP),48(SP),56(SP), R8,R9,R10,R11)
	feMov(R8,R9,R10,R11, R12,R13,R14,R15)

	feNeg(AX,BX,CX,DX)
	feNeg(R8,R9,R10,R11)

	feAdd(AX,BX,CX,DX,  R8, R9,R10,R11) // D
	feAdd(AX,BX,CX,DX, R12,R13,R14,R15) // G

	feMov( R8,R9, R10,R11,  0(SP), 8(SP),16(SP),24(SP))
	feMov(R12,R13,R14,R15, 32(SP),40(SP),48(SP),56(SP))

	// F = G - 2*Z1^2
	feSquare(64(DI), 64(SP))
	feMov(64(SP),72(SP),80(SP),88(SP), R8,R9,R10,R11)
	feDbl(R8,R9,R10,R11)
	feSub(32(SP),40(SP),48(SP),56(SP), R8,R9,R10,R11)
	feMov(R8,R9,R10,R11, 64(SP),72(SP),80(SP),88(SP))

	// E = (X1 + Y1)^2 + D
	feMov( 0(DI), 8(DI),16(DI),24(DI), R8,R9,R10,R11)
	feAdd(32(DI),40(DI),48(DI),56(DI), R8,R9,R10,R11)
	feMov(R8,R9,R10,R11, 96(SP),104(SP),112(SP),120(SP))

	feSquare(96(SP), 96(SP))
	feMov(96(SP),104(SP),112(SP),120(SP), AX,BX,CX,DX)
	feAdd( 0(SP),  8(SP), 16(SP), 24(SP), AX,BX,CX,DX)
	feMov(AX,BX,CX,DX, 96(SP),104(SP),112(SP),120(SP))

	// Layout of stack: D || G || F || E
	feMul(64(SP), 96(SP),  0(DI)) // X3 = F * E
	feMul( 0(SP), 32(SP), 32(DI)) // Y3 = D * G
	feMul(32(SP), 64(SP), 64(DI)) // Z3 = G * F
	feMul( 0(SP), 96(SP), 96(DI)) // T3 = D * E
	RET

// func pMixedAdd(a, b *point)
TEXT ·pMixedAdd(SB),0,$128-16
	MOVQ a+0(FP), DI
	MOVQ b+8(FP), SI

	feMul( 0(DI),  0(SI),  0(SP)) // A = X1 * X2
	feMul(32(DI), 32(SI), 32(SP)) // B = Y1 * Y2

	// D = A + B
	feMov( 0(SP), 8(SP),16(SP),24(SP), R8,R9,R10,R11)
	feAdd(32(SP),40(SP),48(SP),56(SP), R8,R9,R10,R11)
	feMov(R8,R9,R10,R11, 0(SP),8(SP),16(SP),24(SP))

	// E = (X1 + Y1)(X2 + Y2) - D
	feMov( 0(DI), 8(DI),16(DI),24(DI), R8,R9,R10,R11)
	feAdd(32(DI),40(DI),48(DI),56(DI), R8,R9,R10,R11)

	feMov( 0(SI), 8(SI),16(SI),24(SI), R12,R13,R14,R15)
	feAdd(32(SI),40(SI),48(SI),56(SI), R12,R13,R14,R15)

	feMov( R8, R9,R10,R11, 32(SP),40(SP),48(SP),56(SP))
	feMov(R12,R13,R14,R15, 64(SP),72(SP),80(SP),88(SP))

	feMul(32(SP), 64(SP), 32(SP))

	feMov( 0(SP), 8(SP),16(SP),24(SP), R8,R9,R10,R11)
	feSub(32(SP),40(SP),48(SP),56(SP), R8,R9,R10,R11)
	feMov(R8,R9,R10,R11, 32(SP),40(SP),48(SP),56(SP))

	// C = T1 * T2
	feMul(96(DI), 96(SI), 64(SP))

	// G = Z1 + C
	// F = Z1 - C
	feMov(64(DI),72(DI),80(DI),88(DI), AX,BX,CX,DX)
	feMov(AX,BX,CX,DX, R8,R9,R10,R11)
	feMov(64(SP),72(SP),80(SP),88(SP), R12,R13,R14,R15)

	feAdd(R12,R13,R14,R15,  AX, BX, CX, DX) // G
	feSub( R8, R9,R10,R11, R12,R13,R14,R15) // F

	feMov( AX, BX, CX, DX, 64(SP), 72(SP), 80(SP), 88(SP))
	feMov(R12,R13,R14,R15, 96(SP),104(SP),112(SP),120(SP))

	// Layout of stack: D || E || G || F
	feMul(32(SP), 96(SP),  0(DI)) // X3 = E * F
	feMul( 0(SP), 64(SP), 32(DI)) // Y3 = D * F
	feMul(64(SP), 96(SP), 64(DI)) // Z3 = G * F
	feMul( 0(SP), 32(SP), 96(DI)) // T3 = D * E
	RET
