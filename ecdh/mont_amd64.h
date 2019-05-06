// +build amd64

// ladderStepLeg
#define ladderStepLeg()      \
    addSub(x2,z2)            \
    addSub(x3,z3)            \
    integerMul(b0,x2,z3)     \
    integerMul(b1,x3,z2)     \
    reduceFromDouble(t0,b0)  \
    reduceFromDouble(t1,b1)  \
    addSub(t0,t1)            \
    cselect(x2,x3,regMove)   \
    cselect(z2,z3,regMove)   \
    integerSqr(b0,t0)        \
    integerSqr(b1,t1)        \
    reduceFromDouble(x3,b0)  \
    reduceFromDouble(z3,b1)  \
    integerMul(b0,x1,z3)     \
    reduceFromDouble(z3,b0)  \
    integerSqr(b0,x2)        \
    integerSqr(b1,z2)        \
    reduceFromDouble(x2,b0)  \
    reduceFromDouble(z2,b1)  \
    subtraction(t0,x2,z2)    \
    multiplyA24(t1,t0)       \
    addition(t1,t1,z2)       \
    integerMul(b0,x2,z2)     \
    integerMul(b1,t0,t1)     \
    reduceFromDouble(x2,b0)  \
    reduceFromDouble(z2,b1)

// ladderStepBmi2Adx
#define ladderStepBmi2Adx()     \
    addSub(x2,z2)               \
    addSub(x3,z3)               \
    integerMulAdx(b0,x2,z3)     \
    integerMulAdx(b1,x3,z2)     \
    reduceFromDoubleAdx(t0,b0)  \
    reduceFromDoubleAdx(t1,b1)  \
    addSub(t0,t1)               \
    cselect(x2,x3,regMove)      \
    cselect(z2,z3,regMove)      \
    integerSqrAdx(b0,t0)        \
    integerSqrAdx(b1,t1)        \
    reduceFromDoubleAdx(x3,b0)  \
    reduceFromDoubleAdx(z3,b1)  \
    integerMulAdx(b0,x1,z3)     \
    reduceFromDoubleAdx(z3,b0)  \
    integerSqrAdx(b0,x2)        \
    integerSqrAdx(b1,z2)        \
    reduceFromDoubleAdx(x2,b0)  \
    reduceFromDoubleAdx(z2,b1)  \
    subtraction(t0,x2,z2)       \
    multiplyA24Adx(t1,t0)       \
    additionAdx(t1,t1,z2)       \
    integerMulAdx(b0,x2,z2)     \
    integerMulAdx(b1,t0,t1)     \
    reduceFromDoubleAdx(x2,b0)  \
    reduceFromDoubleAdx(z2,b1)

// difAdditionLeg
#define difAdditionLeg()    \
    cswap(x1,x2,regSwap)    \
    cswap(z1,z2,regSwap)    \
    addSub(x1,z1)           \
    integerMul(b0,z1,ui)    \
    reduceFromDouble(z1,b0) \
    addSub(x1,z1)           \
    integerSqr(b0,x1)       \
    integerSqr(b1,z1)       \
    reduceFromDouble(x1,b0) \
    reduceFromDouble(z1,b1) \
    integerMul(b0,x1,z2)    \
    integerMul(b1,z1,x2)    \
    reduceFromDouble(x1,b0) \
    reduceFromDouble(z1,b1)

// difAdditionBmi2Adx
#define difAdditionBmi2Adx()   \
    cswap(x1,x2,regSwap)       \
    cswap(z1,z2,regSwap)       \
    addSub(x1,z1)              \
    integerMulAdx(b0,z1,ui)    \
    reduceFromDoubleAdx(z1,b0) \
    addSub(x1,z1)              \
    integerSqrAdx(b0,x1)       \
    integerSqrAdx(b1,z1)       \
    reduceFromDoubleAdx(x1,b0) \
    reduceFromDoubleAdx(z1,b1) \
    integerMulAdx(b0,x1,z2)    \
    integerMulAdx(b1,z1,x2)    \
    reduceFromDoubleAdx(x1,b0) \
    reduceFromDoubleAdx(z1,b1)

// doubleLeg
#define doubleLeg()         \
    addSub(x1,z1)           \
    integerSqr(b0,x1)       \
    integerSqr(b1,z1)       \
    reduceFromDouble(x1,b0) \
    reduceFromDouble(z1,b1) \
    subtraction(x2,x1,z1)   \
    multiplyA24(z2,x2)      \
    addition(z2,z2,z1)      \
    integerMul(b0,x1,z1)    \
    integerMul(b1,x2,z2)    \
    reduceFromDouble(x1,b0) \
    reduceFromDouble(z1,b1)

// doubleBmi2Adx
#define doubleBmi2Adx()        \
    addSub(x1,z1)              \
    integerSqrAdx(b0,x1)       \
    integerSqrAdx(b1,z1)       \
    reduceFromDoubleAdx(x1,b0) \
    reduceFromDoubleAdx(z1,b1) \
    subtraction(x2,x1,z1)      \
    multiplyA24Adx(z2,x2)      \
    additionAdx(z2,z2,z1)      \
    integerMulAdx(b0,x1,z1)    \
    integerMulAdx(b1,x2,z2)    \
    reduceFromDoubleAdx(x1,b0) \
    reduceFromDoubleAdx(z1,b1)

// EOF

