// @author Armando Faz

// Code imported from https://github.com/armfazh/rfc7748_precomputed

// +build amd64

#include "../fp25519/fp25519_amd64.h"

#define regWork   DI
#define regBuffer SI

#define b0 0*2*SizeField(regBuffer)
#define b1 1*2*SizeField(regBuffer)

#define regMove   CX
#define x2 0*SizeField(regWork)
#define z2 1*SizeField(regWork)
#define x3 2*SizeField(regWork)
#define z3 3*SizeField(regWork)
#define t0 4*SizeField(regWork)
#define t1 5*SizeField(regWork)
#define x1 6*SizeField(regWork)

// func ladderStepX64(work *[7*SizeField]byte, buffer *[4 * SizeField]byte, move uint)
// work = [x2|z2|x3|z3|t0|t1|x1], each term has SizeField bytes.
// buffer = [b0|b1], each has 2*SizeField bytes.
TEXT ·ladderStepX64(SB),NOSPLIT,$0
	MOVQ work+0(FP), regWork
	MOVQ buffer+8(FP), regBuffer

	addSub(x2,z2)
	addSub(x3,z3)
	integerMul(b0,x2,z3)
	integerMul(b1,x3,z2)
	reduceFromDouble(t0,b0)
	reduceFromDouble(t1,b1)
	addSub(t0,t1)

	MOVQ move+16(FP), regMove
	cselect(x2,x3,regMove)
	cselect(z2,z3,regMove)

	integerSqr(b0,t0)
	integerSqr(b1,t1)
	reduceFromDouble(x3,b0)
	reduceFromDouble(z3,b1)
	integerMul(b0,x1,z3)
	reduceFromDouble(z3,b0)
	integerSqr(b0,x2)
	integerSqr(b1,z2)
	reduceFromDouble(x2,b0)
	reduceFromDouble(z2,b1)
	subtraction(t0,x2,z2)
	multiplyA24(t1,t0)
	addition(t1,t1,z2)
	integerMul(b0,x2,z2)
	integerMul(b1,t0,t1)
	reduceFromDouble(x2,b0)
	reduceFromDouble(z2,b1)

	RET

// func ladderStepBmi2Adx(work *[7*SizeField]byte, buffer *[4 * SizeField]byte, move uint)
// work = [x2|z2|x3|z3|t0|t1|x1], each term has SizeField bytes.
// buffer = [b0|b1], each has 2*SizeField bytes.
TEXT ·ladderStepBmi2Adx(SB),NOSPLIT,$0
	MOVQ work+0(FP), regWork
	MOVQ buffer+8(FP), regBuffer

	addSub(x2,z2)
	addSub(x3,z3)
	integerMulAdx(b0,x2,z3)
	integerMulAdx(b1,x3,z2)
	reduceFromDoubleAdx(t0,b0)
	reduceFromDoubleAdx(t1,b1)
	addSub(t0,t1)

	MOVQ move+16(FP), regMove
	cselect(x2,x3,regMove)
	cselect(z2,z3,regMove)

	integerSqrAdx(b0,t0)
	integerSqrAdx(b1,t1)
	reduceFromDoubleAdx(x3,b0)
	reduceFromDoubleAdx(z3,b1)
	integerMulAdx(b0,x1,z3)
	reduceFromDoubleAdx(z3,b0)
	integerSqrAdx(b0,x2)
	integerSqrAdx(b1,z2)
	reduceFromDoubleAdx(x2,b0)
	reduceFromDoubleAdx(z2,b1)
	subtraction(t0,x2,z2)
	multiplyA24Adx(t1,t0)
	additionAdx(t1,t1,z2)
	integerMulAdx(b0,x2,z2)
	integerMulAdx(b1,t0,t1)
	reduceFromDoubleAdx(x2,b0)
	reduceFromDoubleAdx(z2,b1)

	RET

#undef regMove
#undef x2
#undef z2
#undef x3
#undef z3
#undef t0
#undef t1
#undef x1

#define regMu CX
#define regSwap R9
#define x1 0*SizeField(regWork)
#define z1 1*SizeField(regWork)
#define x2 2*SizeField(regWork)
#define z2 3*SizeField(regWork)
#define ui 0(regMu)

// func mixAdditionX64(work *[4 * Fp.SizeField]byte, buffer *[4 * Fp.SizeField]byte, mu *[Fp.SizeField]byte, swap uint)
// work = [x1|z1|x2|z2], each term has SizeField bytes.
// buffer = [b0|b1], each has 2*SizeField bytes.
TEXT ·mixAdditionX64(SB),NOSPLIT,$0
	MOVQ work+0(FP), regWork
	MOVQ buffer+8(FP), regBuffer
	MOVQ mu+16(FP), regMu
	MOVQ swap+24(FP), regSwap

	cswap(x1,x2,regSwap)
	cswap(z1,z2,regSwap)

	addSub(x1,z1)
	integerMul(b0,z1,ui)
	reduceFromDouble(z1,b0)
	addSub(x1,z1)
	integerSqr(b0,x1)
	integerSqr(b1,z1)
	reduceFromDouble(x1,b0)
	reduceFromDouble(z1,b1)
	integerMul(b0,x1,z2)
	integerMul(b1,z1,x2)
	reduceFromDouble(x1,b0)
	reduceFromDouble(z1,b1)

	RET

// func mixAdditionBmi2Adx(work *[4 * Fp.SizeField]byte, buffer *[4 * Fp.SizeField]byte, mu *[Fp.SizeField]byte, swap uint)
// work = [x1|z1|x2|z2], each term has SizeField bytes.
// buffer = [b0|b1], each has 2*SizeField bytes.
TEXT ·mixAdditionBmi2Adx(SB),NOSPLIT,$0
	MOVQ work+0(FP), regWork
	MOVQ buffer+8(FP), regBuffer
	MOVQ mu+16(FP), regMu
	MOVQ swap+24(FP), regSwap

	cswap(x1,x2,regSwap)
	cswap(z1,z2,regSwap)

	addSub(x1,z1)
	integerMulAdx(b0,z1,ui)
	reduceFromDoubleAdx(z1,b0)
	addSub(x1,z1)
	integerSqrAdx(b0,x1)
	integerSqrAdx(b1,z1)
	reduceFromDoubleAdx(x1,b0)
	reduceFromDoubleAdx(z1,b1)
	integerMulAdx(b0,x1,z2)
	integerMulAdx(b1,z1,x2)
	reduceFromDoubleAdx(x1,b0)
	reduceFromDoubleAdx(z1,b1)

	RET

// func doublingX64(work *[4* Fp.SizeField]byte, buffer *[4 * Fp.SizeField]byte)
// work = [x1|z1|x2|z2], each term has SizeField bytes.
// buffer = [b0|b1], each has 2*SizeField bytes.
TEXT ·doublingX64(SB),NOSPLIT,$0
	MOVQ work+0(FP), regWork
	MOVQ buffer+8(FP), regBuffer

	addSub(x1,z1)
	integerSqr(b0,x1)
	integerSqr(b1,z1)
	reduceFromDouble(x1,b0)
	reduceFromDouble(z1,b1)
	subtraction(x2,x1,z1)
	multiplyA24(z2,x2)
	addition(z2,z2,z1)
	integerMul(b0,x1,z1)
	integerMul(b1,x2,z2)
	reduceFromDouble(x1,b0)
	reduceFromDouble(z1,b1)

	RET

// func doublingBmi2Adx(work *[4 * Fp.SizeField]byte, buffer *[4 * Fp.SizeField]byte)
// work = [x1|z1|x2|z2], each term has SizeField bytes.
// buffer = [b0|b1], each has 2*SizeField bytes.
TEXT ·doublingBmi2Adx(SB),NOSPLIT,$0
	MOVQ work+0(FP), regWork
	MOVQ buffer+8(FP), regBuffer

	addSub(x1,z1)
	integerSqrAdx(b0,x1)
	integerSqrAdx(b1,z1)
	reduceFromDoubleAdx(x1,b0)
	reduceFromDoubleAdx(z1,b1)
	subtraction(x2,x1,z1)
	multiplyA24Adx(z2,x2)
	additionAdx(z2,z2,z1)
	integerMulAdx(b0,x1,z1)
	integerMulAdx(b1,x2,z2)
	reduceFromDoubleAdx(x1,b0)
	reduceFromDoubleAdx(z1,b1)
	RET

#undef regWork
#undef regBuffer
#undef regMu
#undef regSwap
#undef b0
#undef b1
#undef x1
#undef z1
#undef x2
#undef z2
#undef ui
