#define bfeMov(a0,a1, c0,c1) \
	MOVQ a0, c0 \
	MOVQ a1, c1

#define bfeReduce(c0,c1) \
	BTRQ $63, c1 \
	ADCQ $0, c0 \
	ADCQ $0, c1

#define bfeNeg(c0,c1) \
	NOTQ c0 \
	NOTQ c1 \
	BTRQ $63, c1

#define bfeDbl(c0,c1) \
	SHLQ $1, c1:c0 \
	SHLQ $1, c0:c1 \
	BTRQ $63, c1

// bfeAdd adds a0:a1 to c0:c1.
#define bfeAdd(a0,a1, c0,c1) \
	ADDQ a0, c0 \
	ADCQ a1, c1 \
	bfeReduce(c0,c1)

// bfeSub stores a0:a1 - c0:c1 in c0:c1.
#define bfeSub(a0,a1, c0,c1) \
	bfeNeg(c0,c1) \
	bfeAdd(a0,a1, c0,c1)
