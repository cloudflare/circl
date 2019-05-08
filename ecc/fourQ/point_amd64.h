#define _double(p) \
    #define Px  const__x_ +p \
    #define Py  const__y_ +p \
    #define Pz  const__z_ +p \
    #define Pta const__ta_+p \
    #define Ptb const__tb_+p \
    #define a Px  \
    #define b Py  \
    #define c Pz  \
    #define d Pta \
    #define e Ptb \
    #define f b   \
    #define g a   \
    _fqAdd(e,Px,Py) \
    _fqSqr(a,Px)    \
    _fqSqr(b,Py)    \
    _fqSqr(c,Pz)    \
    _fqAdd(c,c,c)   \
    _fqAdd(d,a,b)   \
    _fqSqr(e,e)     \
    _fqSub(e,e,d)   \
    _fqSub(f,b,a)   \
    _fqSub(g,c,f)   \
    _fqMul(Pz,f,g)  \
    _fqMul(Px,e,g)  \
    _fqMul(Py,d,f)  \
    #undef Px  \
    #undef Py  \
    #undef Pz  \
    #undef Pta \
    #undef Ptb \
    #undef a   \
    #undef b   \
    #undef c   \
    #undef d   \
    #undef e   \
    #undef f   \
    #undef g

#define _addAsm(p,q,local) \
    #define addYX const__addYX_R2_+q \
    #define subYX const__subYX_R2_+q \
    #define z2    const__z2_R2_   +q \
    #define dt2   const__dt2_R2_  +q \
    #define Px    const__x_ +p \
    #define Py    const__y_ +p \
    #define Pz    const__z_ +p \
    #define Pta   const__ta_+p \
    #define Ptb   const__tb_+p \
    #define a Px    \
    #define b Py    \
    #define c local \
    #define d b     \
    #define e Pta   \
    #define f a     \
    #define g b     \
    #define h Ptb   \
    _fqMul(c, Pta, Ptb) \
    _fqSub(h, b, a)     \
    _fqAdd(b, b, a)     \
    _fqMul(a, h, subYX) \
    _fqMul(b, b, addYX) \
    _fqSub(e, b, a)     \
    _fqAdd(h, b, a)     \
    _fqMul(d, Pz, z2)   \
    _fqMul(c, c, dt2)   \
    _fqSub(f, d, c)     \
    _fqAdd(g, d, c)     \
    _fqMul(Pz, f, g)    \
    _fqMul(Px, e, f)    \
    _fqMul(Py, g, h)    \
    #undef addYX \
    #undef subYX \
    #undef z2    \
    #undef dt2   \
    #undef Px    \
    #undef Py    \
    #undef Pz    \
    #undef Pta   \
    #undef Ptb   \
    #undef a     \
    #undef b     \
    #undef c     \
    #undef d     \
    #undef e     \
    #undef f     \
    #undef g     \
    #undef h

#define _mixAddAsm(p,q,local) \
    #define addYX const__addYX_R3_+q \
    #define subYX const__subYX_R3_+q \
    #define dt2   const__dt2_R3_  +q \
    #define Px    const__x_ +p \
    #define Py    const__y_ +p \
    #define Pz    const__z_ +p \
    #define Pta   const__ta_+p \
    #define Ptb   const__tb_+p \
    #define a Px    \
    #define b Py    \
    #define c local \
    #define d b     \
    #define e Pta   \
    #define f a     \
    #define g b     \
    #define h Ptb   \
    _fqMul(c, Pta, Ptb) \
    _fqSub(h, b, a)     \
    _fqAdd(b, b, a)     \
    _fqMul(a, h, subYX) \
    _fqMul(b, b, addYX) \
    _fqSub(e, b, a)     \
    _fqAdd(h, b, a)     \
    _fqAdd(d, Pz, Pz)   \
    _fqMul(c, c, dt2)   \
    _fqSub(f, d, c)     \
    _fqAdd(g, d, c)     \
    _fqMul(Pz, f, g)    \
    _fqMul(Px, e, f)    \
    _fqMul(Py, g, h)    \
    #undef addYX \
    #undef subYX \
    #undef dt2   \
    #undef Px    \
    #undef Py    \
    #undef Pz    \
    #undef Pta   \
    #undef Ptb   \
    #undef a     \
    #undef b     \
    #undef c     \
    #undef d     \
    #undef e     \
    #undef f     \
    #undef g     \
    #undef h
