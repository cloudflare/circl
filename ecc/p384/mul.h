#define mul(a0,a1,a2,a3,a4,a5, rb, stack) \
	\ // a0
	MOVQ a0, AX \
	MULQ 0+rb \
	MOVQ AX, R8 \
	MOVQ DX, R9 \
	MOVQ a0, AX \
	MULQ 8+rb \
	ADDQ AX, R9 \
	ADCQ $0, DX \
	MOVQ DX, R10 \
	MOVQ a0, AX \
	MULQ 16+rb \
	ADDQ AX, R10 \
	ADCQ $0, DX \
	MOVQ DX, R11 \
	MOVQ a0, AX \
	MULQ 24+rb \
	ADDQ AX, R11 \
	ADCQ $0, DX \
	MOVQ DX, R12 \
	MOVQ a0, AX \
	MULQ 32+rb \
	ADDQ AX, R12 \
	ADCQ $0, DX \
	MOVQ DX, R13 \
	MOVQ a0, AX \
	MULQ 40+rb \
	ADDQ AX, R13 \
	ADCQ $0, DX \
	MOVQ DX, R14 \
	\
	storeBlock(R8,R9,R10,R11,R12,R13, 0+stack) \
	MOVQ R14, 48+stack \
	\
	\ // a1
	MOVQ a1, AX \
	MULQ 0+rb \
	MOVQ AX, R8 \
	MOVQ DX, R9 \
	MOVQ a1, AX \
	MULQ 8+rb \
	ADDQ AX, R9 \
	ADCQ $0, DX \
	MOVQ DX, R10 \
	MOVQ a1, AX \
	MULQ 16+rb \
	ADDQ AX, R10 \
	ADCQ $0, DX \
	MOVQ DX, R11 \
	MOVQ a1, AX \
	MULQ 24+rb \
	ADDQ AX, R11 \
	ADCQ $0, DX \
	MOVQ DX, R12 \
	MOVQ a1, AX \
	MULQ 32+rb \
	ADDQ AX, R12 \
	ADCQ $0, DX \
	MOVQ DX, R13 \
	MOVQ a1, AX \
	MULQ 40+rb \
	ADDQ AX, R13 \
	ADCQ $0, DX \
	MOVQ DX, R14 \
	\
	ADDQ 8+stack, R8 \
	ADCQ 16+stack, R9 \
	ADCQ 24+stack, R10 \
	ADCQ 32+stack, R11 \
	ADCQ 40+stack, R12 \
	ADCQ 48+stack, R13 \
	ADCQ $0, R14 \
	storeBlock(R8,R9,R10,R11,R12,R13, 8+stack) \
	MOVQ R14, 56+stack \
	\
	\ // a2
	MOVQ a2, AX \
	MULQ 0+rb \
	MOVQ AX, R8 \
	MOVQ DX, R9 \
	MOVQ a2, AX \
	MULQ 8+rb \
	ADDQ AX, R9 \
	ADCQ $0, DX \
	MOVQ DX, R10 \
	MOVQ a2, AX \
	MULQ 16+rb \
	ADDQ AX, R10 \
	ADCQ $0, DX \
	MOVQ DX, R11 \
	MOVQ a2, AX \
	MULQ 24+rb \
	ADDQ AX, R11 \
	ADCQ $0, DX \
	MOVQ DX, R12 \
	MOVQ a2, AX \
	MULQ 32+rb \
	ADDQ AX, R12 \
	ADCQ $0, DX \
	MOVQ DX, R13 \
	MOVQ a2, AX \
	MULQ 40+rb \
	ADDQ AX, R13 \
	ADCQ $0, DX \
	MOVQ DX, R14 \
	\
	ADDQ 16+stack, R8 \
	ADCQ 24+stack, R9 \
	ADCQ 32+stack, R10 \
	ADCQ 40+stack, R11 \
	ADCQ 48+stack, R12 \
	ADCQ 56+stack, R13 \
	ADCQ $0, R14 \
	storeBlock(R8,R9,R10,R11,R12,R13, 16+stack) \
	MOVQ R14, 64+stack \
	\
	\ // a3
	MOVQ a3, AX \
	MULQ 0+rb \
	MOVQ AX, R8 \
	MOVQ DX, R9 \
	MOVQ a3, AX \
	MULQ 8+rb \
	ADDQ AX, R9 \
	ADCQ $0, DX \
	MOVQ DX, R10 \
	MOVQ a3, AX \
	MULQ 16+rb \
	ADDQ AX, R10 \
	ADCQ $0, DX \
	MOVQ DX, R11 \
	MOVQ a3, AX \
	MULQ 24+rb \
	ADDQ AX, R11 \
	ADCQ $0, DX \
	MOVQ DX, R12 \
	MOVQ a3, AX \
	MULQ 32+rb \
	ADDQ AX, R12 \
	ADCQ $0, DX \
	MOVQ DX, R13 \
	MOVQ a3, AX \
	MULQ 40+rb \
	ADDQ AX, R13 \
	ADCQ $0, DX \
	MOVQ DX, R14 \
	\
	ADDQ 24+stack, R8 \
	ADCQ 32+stack, R9 \
	ADCQ 40+stack, R10 \
	ADCQ 48+stack, R11 \
	ADCQ 56+stack, R12 \
	ADCQ 64+stack, R13 \
	ADCQ $0, R14 \
	storeBlock(R8,R9,R10,R11,R12,R13, 24+stack) \
	MOVQ R14, 72+stack \
	\
	\ // a4
	MOVQ a4, AX \
	MULQ 0+rb \
	MOVQ AX, R8 \
	MOVQ DX, R9 \
	MOVQ a4, AX \
	MULQ 8+rb \
	ADDQ AX, R9 \
	ADCQ $0, DX \
	MOVQ DX, R10 \
	MOVQ a4, AX \
	MULQ 16+rb \
	ADDQ AX, R10 \
	ADCQ $0, DX \
	MOVQ DX, R11 \
	MOVQ a4, AX \
	MULQ 24+rb \
	ADDQ AX, R11 \
	ADCQ $0, DX \
	MOVQ DX, R12 \
	MOVQ a4, AX \
	MULQ 32+rb \
	ADDQ AX, R12 \
	ADCQ $0, DX \
	MOVQ DX, R13 \
	MOVQ a4, AX \
	MULQ 40+rb \
	ADDQ AX, R13 \
	ADCQ $0, DX \
	MOVQ DX, R14 \
	\
	ADDQ 32+stack, R8 \
	ADCQ 40+stack, R9 \
	ADCQ 48+stack, R10 \
	ADCQ 56+stack, R11 \
	ADCQ 64+stack, R12 \
	ADCQ 72+stack, R13 \
	ADCQ $0, R14 \
	storeBlock(R8,R9,R10,R11,R12,R13, 32+stack) \
	MOVQ R14, 80+stack \
	\
	\ // a5
	MOVQ a5, AX \
	MULQ 0+rb \
	MOVQ AX, R8 \
	MOVQ DX, R9 \
	MOVQ a5, AX \
	MULQ 8+rb \
	ADDQ AX, R9 \
	ADCQ $0, DX \
	MOVQ DX, R10 \
	MOVQ a5, AX \
	MULQ 16+rb \
	ADDQ AX, R10 \
	ADCQ $0, DX \
	MOVQ DX, R11 \
	MOVQ a5, AX \
	MULQ 24+rb \
	ADDQ AX, R11 \
	ADCQ $0, DX \
	MOVQ DX, R12 \
	MOVQ a5, AX \
	MULQ 32+rb \
	ADDQ AX, R12 \
	ADCQ $0, DX \
	MOVQ DX, R13 \
	MOVQ a5, AX \
	MULQ 40+rb \
	ADDQ AX, R13 \
	ADCQ $0, DX \
	MOVQ DX, R14 \
	\
	ADDQ 40+stack, R8 \
	ADCQ 48+stack, R9 \
	ADCQ 56+stack, R10 \
	ADCQ 64+stack, R11 \
	ADCQ 72+stack, R12 \
	ADCQ 80+stack, R13 \
	ADCQ $0, R14 \
	storeBlock(R8,R9,R10,R11,R12,R13, 40+stack) \
	MOVQ R14, 88+stack

#define gfpReduce(stack) \
	\ // m = (T * P') mod R, store m in R8:R9:R10:R11:R12:R13
	MOVQ ·pp+0(SB), AX \
	MULQ 0+stack \
	MOVQ AX, R8 \
	MOVQ DX, R9 \
	MOVQ ·pp+0(SB), AX \
	MULQ 8+stack \
	ADDQ AX, R9 \
	ADCQ $0, DX \
	MOVQ DX, R10 \
	MOVQ ·pp+0(SB), AX \
	MULQ 16+stack \
	ADDQ AX, R10 \
	ADCQ $0, DX \
	MOVQ DX, R11 \
	MOVQ ·pp+0(SB), AX \
	MULQ 24+stack \
	ADDQ AX, R11 \
	ADCQ $0, DX \
	MOVQ DX, R12 \
	MOVQ ·pp+0(SB), AX \
	MULQ 32+stack \
	ADDQ AX, R12 \
	ADCQ $0, DX \
	MOVQ DX, R13 \
	MOVQ ·pp+0(SB), AX \
	MULQ 40+stack \
	ADDQ AX, R13 \
	\
	ADDQ 0+stack, R9 \
	ADCQ 8+stack, R10 \
	ADCQ 16+stack, R11 \
	ADCQ 24+stack, R12 \
	ADCQ 32+stack, R13 \
	\
	MOVQ ·pp+16(SB), AX \
	MULQ 0+stack \
	MOVQ AX, R14 \
	MOVQ DX, R15 \
	MOVQ ·pp+16(SB), AX \
	MULQ 8+stack \
	ADDQ AX, R15 \
	ADCQ $0, DX \
	MOVQ DX, BX \
	MOVQ ·pp+16(SB), AX \
	MULQ 16+stack \
	ADDQ AX, BX \
	ADCQ $0, DX \
	MOVQ DX, CX \
	MOVQ ·pp+16(SB), AX \
	MULQ 24+stack \
	ADDQ AX, CX \
	\
	ADDQ R14, R10 \
	ADCQ R15, R11 \
	ADCQ BX, R12 \
	ADCQ CX, R13 \
	\
	MOVQ ·pp+24(SB), AX \
	MULQ 0+stack \
	MOVQ AX, R14 \
	MOVQ DX, R15 \
	MOVQ ·pp+24(SB), AX \
	MULQ 8+stack \
	ADDQ AX, R15 \
	ADCQ $0, DX \
	MOVQ DX, BX \
	MOVQ ·pp+24(SB), AX \
	MULQ 16+stack \
	ADDQ AX, BX \
	\
	ADDQ R14, R11 \
	ADCQ R15, R12 \
	ADCQ BX, R13 \
	\
	MOVQ ·pp+32(SB), AX \
	MULQ 0+stack \
	MOVQ AX, R14 \
	MOVQ DX, R15 \
	MOVQ ·pp+32(SB), AX \
	MULQ 8+stack \
	ADDQ AX, R15 \
	\
	ADDQ R14, R12 \
	ADCQ R15, R13 \
	\
	MOVQ ·pp+40(SB), AX \
	MULQ 0+stack \
	ADDQ AX, R13 \
	\
	storeBlock(R8,R9,R10,R11,R12,R13, 96+stack) \
	\
	\ // m * P
	mul(·p+0(SB),·p+8(SB),·p+16(SB),·p+24(SB),·p+32(SB),·p+40(SB), 96+stack, 144+stack) \
	\
	\ // Add the 768-bit intermediate to m*N
	MOVQ $0, DI \
	loadBlock(144+stack, R8,R9,R10,R11,R12,R13) \
	loadBlock(192+stack, R14,R15,AX,BX,CX,DX) \
	\
	ADDQ 0+stack, R8 \
	ADCQ 8+stack, R9 \
	ADCQ 16+stack, R10 \
	ADCQ 24+stack, R11 \
	ADCQ 32+stack, R12 \
	ADCQ 40+stack, R13 \
	ADCQ 48+stack, R14 \
	ADCQ 56+stack, R15 \
	ADCQ 64+stack, AX \
	ADCQ 72+stack, BX \
	ADCQ 80+stack, CX \
	ADCQ 88+stack, DX \
	ADCQ $0, DI \
	\
	gfpCarry(R14,R15,AX,BX,CX,DX,DI, R8,R9,R10,R11,R12,R13,SI)
