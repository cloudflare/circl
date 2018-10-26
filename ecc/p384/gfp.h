#define storeBlock(a0,a1,a2,a3,a4,a5, r) \
	MOVQ a0,  0+r \
	MOVQ a1,  8+r \
	MOVQ a2, 16+r \
	MOVQ a3, 24+r \
	MOVQ a4, 32+r \
	MOVQ a5, 40+r \

#define loadBlock(r, a0,a1,a2,a3,a4,a5) \
	MOVQ  0+r, a0 \
	MOVQ  8+r, a1 \
	MOVQ 16+r, a2 \
	MOVQ 24+r, a3 \
	MOVQ 32+r, a4 \
	MOVQ 40+r, a5

#define gfpCarry(a0,a1,a2,a3,a4,a5,a6, b0,b1,b2,b3,b4,b5,b6) \
	\ // b = a-p
	MOVQ a0, b0 \
	MOVQ a1, b1 \
	MOVQ a2, b2 \
	MOVQ a3, b3 \
	MOVQ a4, b4 \
	MOVQ a5, b5 \
	MOVQ a6, b6 \
	\
	SUBQ ·p+0(SB), b0 \
	SBBQ ·p+8(SB), b1 \
	SBBQ ·p+16(SB), b2 \
	SBBQ ·p+24(SB), b3 \
	SBBQ ·p+32(SB), b4 \
	SBBQ ·p+40(SB), b5 \
	SBBQ $0, b6 \
	\
	\ // if b is negative then return a
	\ // else return b
	CMOVQCC b0, a0 \
	CMOVQCC b1, a1 \
	CMOVQCC b2, a2 \
	CMOVQCC b3, a3 \
	CMOVQCC b4, a4 \
	CMOVQCC b5, a5
