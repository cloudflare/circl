#define mulBMI2(a0,a1,a2,a3,a4,a5, rb, stack) \
	MOVQ a0, DX \
	MULXQ 0+rb, R8, R9 \
	MULXQ 8+rb, AX, R10 \
	ADDQ AX, R9 \
	MULXQ 16+rb, AX, R11 \
	ADCQ AX, R10 \
	MULXQ 24+rb, AX, R12 \
	ADCQ AX, R11 \
	MULXQ 32+rb, AX, R13 \
	ADCQ AX, R12 \
	MULXQ 40+rb, AX, R14 \
	ADCQ AX, R13 \
	ADCQ $0, R14 \
	\
	MOVQ R8, 0+stack \
	MOVQ $0, R15 \
	MOVQ $0, R8 \
	\
	MOVQ a1, DX \
	MULXQ 0+rb, AX, BX \
	ADDQ AX, R9 \
	ADCQ BX, R10 \
	MULXQ 16+rb, AX, BX \
	ADCQ AX, R11 \
	ADCQ BX, R12 \
	MULXQ 32+rb, AX, BX \
	ADCQ AX, R13 \
	ADCQ BX, R14 \
	ADCQ $0, R15 \
	MULXQ 8+rb, AX, BX \
	ADDQ AX, R10 \
	ADCQ BX, R11 \
	MULXQ 24+rb, AX, BX \
	ADCQ AX, R12 \
	ADCQ BX, R13 \
	MULXQ 40+rb, AX, BX \
	ADCQ AX, R14 \
	ADCQ BX, R15 \
	ADCQ $0, R8 \
	\
	MOVQ R9, 8+stack \
	MOVQ $0, R9 \
	\
	MOVQ a2, DX \
	MULXQ 0+rb, AX, BX \
	ADDQ AX, R10 \
	ADCQ BX, R11 \
	MULXQ 16+rb, AX, BX \
	ADCQ AX, R12 \
	ADCQ BX, R13 \
	MULXQ 32+rb, AX, BX \
	ADCQ AX, R14 \
	ADCQ BX, R15 \
	ADCQ $0, R8 \
	MULXQ 8+rb, AX, BX \
	ADDQ AX, R11 \
	ADCQ BX, R12 \
	MULXQ 24+rb, AX, BX \
	ADCQ AX, R13 \
	ADCQ BX, R14 \
	MULXQ 40+rb, AX, BX \
	ADCQ AX, R15 \
	ADCQ BX, R8 \
	ADCQ $0, R9 \
	\
	MOVQ R10, 16+stack \
	MOVQ $0, R10 \
	\
	MOVQ a3, DX \
	MULXQ 0+rb, AX, BX \
	ADDQ AX, R11 \
	ADCQ BX, R12 \
	MULXQ 16+rb, AX, BX \
	ADCQ AX, R13 \
	ADCQ BX, R14 \
	MULXQ 32+rb, AX, BX \
	ADCQ AX, R15 \
	ADCQ BX, R8 \
	ADCQ $0, R9 \
	MULXQ 8+rb, AX, BX \
	ADDQ AX, R12 \
	ADCQ BX, R13 \
	MULXQ 24+rb, AX, BX \
	ADCQ AX, R14 \
	ADCQ BX, R15 \
	MULXQ 40+rb, AX, BX \
	ADCQ AX, R8 \
	ADCQ BX, R9 \
	ADCQ $0, R10 \
	\
	MOVQ R11, 24+stack \
	MOVQ $0, R11 \
	\
	MOVQ a4, DX \
	MULXQ 0+rb, AX, BX \
	ADDQ AX, R12 \
	ADCQ BX, R13 \
	MULXQ 16+rb, AX, BX \
	ADCQ AX, R14 \
	ADCQ BX, R15 \
	MULXQ 32+rb, AX, BX \
	ADCQ AX, R8 \
	ADCQ BX, R9 \
	ADCQ $0, R10 \
	MULXQ 8+rb, AX, BX \
	ADDQ AX, R13 \
	ADCQ BX, R14 \
	MULXQ 24+rb, AX, BX \
	ADCQ AX, R15 \
	ADCQ BX, R8 \
	MULXQ 40+rb, AX, BX \
	ADCQ AX, R9 \
	ADCQ BX, R10 \
	ADCQ $0, R11 \
	\
	MOVQ R12, 32+stack \
	\
	MOVQ a5, DX \
	MULXQ 0+rb, AX, BX \
	ADDQ AX, R13 \
	ADCQ BX, R14 \
	MULXQ 16+rb, AX, BX \
	ADCQ AX, R15 \
	ADCQ BX, R8 \
	MULXQ 32+rb, AX, BX \
	ADCQ AX, R9 \
	ADCQ BX, R10 \
	ADCQ $0, R11 \
	MULXQ 8+rb, AX, BX \
	ADDQ AX, R14 \
	ADCQ BX, R15 \
	MULXQ 24+rb, AX, BX \
	ADCQ AX, R8 \
	ADCQ BX, R9 \
	MULXQ 40+rb, AX, BX \
	ADCQ AX, R10 \
	ADCQ BX, R11 \
	\
	MOVQ R13, 40+stack

#define gfpReduceBMI2(stack) \
	\ // m = (T * P') mod R, store m in R8:R9:R10:R11:R12:R13
	MOVQ ·pp+0(SB), DX \
	MULXQ 0+stack, R8, R9 \
	MULXQ 8+stack, AX, R10 \
	ADDQ AX, R9 \
	MULXQ 16+stack, AX, R11 \
	ADCQ AX, R10 \
	MULXQ 24+stack, AX, R12 \
	ADCQ AX, R11 \
	MULXQ 32+stack, AX, R13 \
	ADCQ AX, R12 \
	MULXQ 40+stack, AX, BX \
	ADCQ AX, R13 \
	\
	ADDQ 0+stack, R9 \
	ADCQ 8+stack, R10 \
	ADCQ 16+stack, R11 \
	ADCQ 24+stack, R12 \
	ADCQ 32+stack, R13 \
	\
	MOVQ ·pp+16(SB), DX \
	MULXQ 0+stack, AX, BX \
	ADDQ AX, R10 \
	ADCQ BX, R11 \
	MULXQ 16+stack, AX, BX \
	ADCQ AX, R12 \
	ADCQ BX, R13 \
	MULXQ 8+stack, AX, BX \
	ADDQ AX, R11 \
	ADCQ BX, R12 \
	MULXQ 24+stack, AX, BX \
	ADCQ AX, R13 \
	\
	MOVQ ·pp+24(SB), DX \
	MULXQ 0+stack, AX, BX \
	ADDQ AX, R11 \
	ADCQ BX, R12 \
	MULXQ 16+stack, AX, BX \
	ADCQ AX, R13 \
	MULXQ 8+stack, AX, BX \
	ADDQ AX, R12 \
	ADCQ BX, R13 \
	\
	MOVQ ·pp+32(SB), DX \
	MULXQ 0+stack, AX, BX \
	ADDQ AX, R12 \
	ADCQ BX, R13 \
	MULXQ 8+stack, AX, BX \
	ADDQ AX, R13 \
	\
	MOVQ ·pp+40(SB), DX \
	MULXQ 0+stack, AX, BX \
	ADDQ AX, R13 \
	\
	storeBlock(R8,R9,R10,R11,R12,R13, 96+stack) \
	\
	\ // m * P
	mulBMI2(·p+0(SB),·p+8(SB),·p+16(SB),·p+24(SB),·p+32(SB),·p+40(SB), 96+stack, 144+stack) \
	\
	\ // Add the 768-bit intermediate to m*N
	MOVQ $0, AX \
	loadBlock(144+stack, R12,R13,BX,CX,DX,DI) \
	\
	ADDQ 0+stack, R12 \
	ADCQ 8+stack, R13 \
	ADCQ 16+stack, BX \
	ADCQ 24+stack, CX \
	ADCQ 32+stack, DX \
	ADCQ 40+stack, DI \
	ADCQ 48+stack, R14 \
	ADCQ 56+stack, R15 \
	ADCQ 64+stack, R8 \
	ADCQ 72+stack, R9 \
	ADCQ 80+stack, R10 \
	ADCQ 88+stack, R11 \
	ADCQ $0, AX \
	\
	gfpCarry(R14,R15,R8,R9,R10,R11,AX, R12,R13,BX,CX,DX,DI,SI)
