package fourq

import (
	"crypto/subtle"
	"math/big"
)

// Fq implements operations of a field of size q=p^2 as a quadratic
// extension of the base field where i^2=-1.
// An element in Fq is represented as f[0]+f[1]*i, where f[0],f[1] are in Fp.
type Fq [2]Fp

func (e *Fq) String() string              { return e[1].String() + " *i+ " + e[0].String() }
func (e *Fq) toBigInt() (f0, f1 *big.Int) { return e[0].toBigInt(), e[1].toBigInt() }
func (e *Fq) setBigInt(f0, f1 *big.Int)   { e[0].setBigInt(f0); e[1].setBigInt(f1) }
func (e *Fq) setZero()                    { var z Fp; e[0] = z; e[1] = z }
func (e *Fq) setOne()                     { e.setZero(); e[0][0] = 1 }
func (e *Fq) isZero() bool                { return e[0].isZero() && e[1].isZero() }

func (e *Fq) toBytes(buf []byte) {
	if len(buf) == 2*SizeFp {
		e[0].toBytes(buf[:SizeFp])
		e[1].toBytes(buf[SizeFp:])
	}
}

func (e *Fq) fromBytes(buf []byte) bool {
	if len(buf) == 2*SizeFp {
		return e[0].fromBytes(buf[:SizeFp]) &&
			e[1].fromBytes(buf[SizeFp:])
	}
	return false
}

func fqSgn(c *Fq) int {
	s0 := fpSgn(&c[0])
	s1 := fpSgn(&c[1])
	return subtle.ConstantTimeSelect(s0&0x1, s0, s1)
}
func fqCopy(c, a *Fq) { *c = *a }
func fqNeg(c, a *Fq)  { fpNeg(&c[0], &a[0]); fpNeg(&c[1], &a[1]) }

// fqSqrt calculates c = sqrt(u/v) such that sgn(c)=s.
func fqSqrt(c, u, v *Fq, s int) {
	t0, t1, t, r := &Fp{}, &Fp{}, &Fp{}, &Fp{}
	a, b, g := &Fp{}, &Fp{}, &Fp{}

	// a = u0*v0 + u1*v1
	fpMul(a, &u[0], &v[0])
	fpMul(t0, &u[1], &v[1])
	fpAdd(a, a, t0)

	// b = v0^2 + v1^2
	fpSqr(b, &v[0])
	fpSqr(t0, &v[1])
	fpAdd(b, b, t0)

	// g = u1*v0 - u0*v1
	fpMul(g, &u[1], &v[0])
	fpMul(t0, &u[0], &v[1])
	fpSub(g, g, t0)

	// t = 2(a + sqrt(a^2+g^2)) = 2*(a + (a^2+g^2)^(2^125))
	// if t=0; then t = 2*(a - (a^2+g^2)^(2^125))
	fpSqr(t0, a)
	fpSqr(t1, g)
	fpAdd(t0, t0, t1)
	for i := 0; i < 125; i++ {
		fpSqr(t0, t0)
	}
	fpAdd(t, a, t0)
	if t.isZero() {
		fpSub(t, a, t0)
	}
	fpAdd(t, t, t)

	// r = (t*b^3)^(2^125-1)
	fpSqr(r, b)
	fpMul(r, r, b)
	fpMul(r, r, t)
	fpTwo1251(r, r)

	// x0 = (r*b*t)/2
	// x1 = (r*b*g)
	fpMul(&c[1], r, b)
	fpMul(&c[0], &c[1], t)
	fpHlf(&c[0], &c[0])
	fpMul(&c[1], &c[1], g)

	// if b*(2*x0)^2 == t then (x0,x1) <- (x1,x0)
	fpAdd(t0, &c[0], &c[0])
	fpSqr(t0, t0)
	fpMul(t0, t0, b)
	fpSub(t0, t0, t)
	if !t0.isZero() {
		*t0 = c[0]
		c[0] = c[1]
		c[1] = *t0
	}

	if fqSgn(c) != s {
		fqNeg(c, c)
	}
}

func fqInv(c, a *Fq) {
	t1, t2 := &Fp{}, &Fp{}
	fpSqr(t1, &a[0])
	fpSqr(t2, &a[1])
	fpAdd(t1, t1, t2)
	fpInv(t1, t1)
	fpMul(&c[0], &a[0], t1)
	fpNeg(t1, t1)
	fpMul(&c[1], &a[1], t1)
}
