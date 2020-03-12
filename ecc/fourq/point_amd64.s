// +build amd64,!purego

#include "go_asm.h"
#include "fq_amd64.h"
#include "point_amd64.h"

// func doubleAsm(P *pointR1)
TEXT ·doubleAsm(SB),0,$0-8
    MOVQ P+0(FP), DI
    _double(0(DI))
    RET

// func addAsm(P *pointR1, R *pointR2)
TEXT ·addAsm(SB),0,$32-16
    MOVQ P+0(FP), DI
    MOVQ Q+8(FP), SI
    _addAsm(0(DI),0(SI),0(SP))
    RET

// func mixAddAsm(P *pointR1, Q *pointR3)
TEXT ·mixAddAsm(SB),0,$32-16
    MOVQ P+0(FP), DI
    MOVQ Q+8(FP), SI
    _mixAddAsm(0(DI),0(SI),0(SP))
    RET
