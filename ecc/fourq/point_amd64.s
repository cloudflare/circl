// +build amd64,!purego

#include "go_asm.h"
#include "fq_amd64.h"
#include "point_amd64.h"

// func doubleAmd64(P *pointR1)
TEXT ·doubleAmd64(SB),0,$0-8
    MOVQ P+0(FP), DI
    #define Px  const__x +0(DI)
    #define Py  const__y +0(DI)
    #define Pz  const__z +0(DI)
    #define Pta const__ta+0(DI)
    #define Ptb const__tb+0(DI)
    #define a Px
    #define b Py
    #define c Pz
    #define d Pta
    #define e Ptb
    #define f b
    #define g a
    CHECK_BMI2(LDOUBLE, doubleLeg, doubleBmi2)
    #undef Px
    #undef Py
    #undef Pz
    #undef Pta
    #undef Ptb
    #undef a
    #undef b
    #undef c
    #undef d
    #undef e
    #undef f
    #undef g

// func addAmd64(P *pointR1, R *pointR2)
TEXT ·addAmd64(SB),0,$32-16
    MOVQ P+0(FP), DI
    MOVQ Q+8(FP), SI
    #define addYX const__addYXR2+0(SI)
    #define subYX const__subYXR2+0(SI)
    #define z2    const__z2R2   +0(SI)
    #define dt2   const__dt2R2  +0(SI)
    #define Px    const__x +0(DI)
    #define Py    const__y +0(DI)
    #define Pz    const__z +0(DI)
    #define Pta   const__ta+0(DI)
    #define Ptb   const__tb+0(DI)
    #define a Px
    #define b Py
    #define c 0(SP)
    #define d b
    #define e Pta
    #define f a
    #define g b
    #define h Ptb
    CHECK_BMI2(LDADD, addLeg, addBmi2)
    #undef addYX
    #undef subYX
    #undef z2
    #undef dt2
    #undef Px
    #undef Py
    #undef Pz
    #undef Pta
    #undef Ptb
    #undef a
    #undef b
    #undef c
    #undef d
    #undef e
    #undef f
    #undef g
    #undef h

// func mixAddAmd64(P *pointR1, Q *pointR3)
TEXT ·mixAddAmd64(SB),0,$32-16
    MOVQ P+0(FP), DI
    MOVQ Q+8(FP), SI
    #define addYX const__addYXR3+0(SI)
    #define subYX const__subYXR3+0(SI)
    #define dt2   const__dt2R3  +0(SI)
    #define Px    const__x +0(DI)
    #define Py    const__y +0(DI)
    #define Pz    const__z +0(DI)
    #define Pta   const__ta+0(DI)
    #define Ptb   const__tb+0(DI)
    #define a Px
    #define b Py
    #define c 0(SP)
    #define d b
    #define e Pta
    #define f a
    #define g b
    #define h Ptb
    CHECK_BMI2(LDMIXADD, mixAddLeg, mixAddBmi2)
    #undef addYX
    #undef subYX
    #undef dt2
    #undef Px
    #undef Py
    #undef Pz
    #undef Pta
    #undef Ptb
    #undef a
    #undef b
    #undef c
    #undef d
    #undef e
    #undef f
    #undef g
    #undef h
