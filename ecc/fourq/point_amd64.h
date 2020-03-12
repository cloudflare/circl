#define doubleLeg     \
    _fqAdd(e,Px,Py)   \
    _fqSqrLeg(a,Px)   \
    _fqSqrLeg(b,Py)   \
    _fqSqrLeg(c,Pz)   \
    _fqAdd(c,c,c)     \
    _fqAdd(d,a,b)     \
    _fqSqrLeg(e,e)    \
    _fqSub(e,e,d)     \
    _fqSub(f,b,a)     \
    _fqSub(g,c,f)     \
    _fqMulLeg(Pz,f,g) \
    _fqMulLeg(Px,e,g) \
    _fqMulLeg(Py,d,f)

#define doubleBmi2     \
    _fqAdd(e,Px,Py)    \
    _fqSqrBmi2(a,Px)   \
    _fqSqrBmi2(b,Py)   \
    _fqSqrBmi2(c,Pz)   \
    _fqAdd(c,c,c)      \
    _fqAdd(d,a,b)      \
    _fqSqrBmi2(e,e)    \
    _fqSub(e,e,d)      \
    _fqSub(f,b,a)      \
    _fqSub(g,c,f)      \
    _fqMulBmi2(Pz,f,g) \
    _fqMulBmi2(Px,e,g) \
    _fqMulBmi2(Py,d,f)

#define addLeg             \
    _fqMulLeg(c, Pta, Ptb) \
    _fqSub(h, b, a)        \
    _fqAdd(b, b, a)        \
    _fqMulLeg(a, h, subYX) \
    _fqMulLeg(b, b, addYX) \
    _fqSub(e, b, a)        \
    _fqAdd(h, b, a)        \
    _fqMulLeg(d, Pz, z2)   \
    _fqMulLeg(c, c, dt2)   \
    _fqSub(f, d, c)        \
    _fqAdd(g, d, c)        \
    _fqMulLeg(Pz, f, g)    \
    _fqMulLeg(Px, e, f)    \
    _fqMulLeg(Py, g, h)

#define addBmi2             \
    _fqMulBmi2(c, Pta, Ptb) \
    _fqSub(h, b, a)         \
    _fqAdd(b, b, a)         \
    _fqMulBmi2(a, h, subYX) \
    _fqMulBmi2(b, b, addYX) \
    _fqSub(e, b, a)         \
    _fqAdd(h, b, a)         \
    _fqMulBmi2(d, Pz, z2)   \
    _fqMulBmi2(c, c, dt2)   \
    _fqSub(f, d, c)         \
    _fqAdd(g, d, c)         \
    _fqMulBmi2(Pz, f, g)    \
    _fqMulBmi2(Px, e, f)    \
    _fqMulBmi2(Py, g, h)

#define mixAddLeg          \
    _fqMulLeg(c, Pta, Ptb) \
    _fqSub(h, b, a)        \
    _fqAdd(b, b, a)        \
    _fqMulLeg(a, h, subYX) \
    _fqMulLeg(b, b, addYX) \
    _fqSub(e, b, a)        \
    _fqAdd(h, b, a)        \
    _fqAdd(d, Pz, Pz)      \
    _fqMulLeg(c, c, dt2)   \
    _fqSub(f, d, c)        \
    _fqAdd(g, d, c)        \
    _fqMulLeg(Pz, f, g)    \
    _fqMulLeg(Px, e, f)    \
    _fqMulLeg(Py, g, h)

#define mixAddBmi2          \
    _fqMulBmi2(c, Pta, Ptb) \
    _fqSub(h, b, a)         \
    _fqAdd(b, b, a)         \
    _fqMulBmi2(a, h, subYX) \
    _fqMulBmi2(b, b, addYX) \
    _fqSub(e, b, a)         \
    _fqAdd(h, b, a)         \
    _fqAdd(d, Pz, Pz)       \
    _fqMulBmi2(c, c, dt2)   \
    _fqSub(f, d, c)         \
    _fqAdd(g, d, c)         \
    _fqMulBmi2(Pz, f, g)    \
    _fqMulBmi2(Px, e, f)    \
    _fqMulBmi2(Py, g, h)
