package ff

// Cyclo6 represents an element of the 6th cyclotomic group.
type Cyclo6 Fp12

func (z Cyclo6) String() string           { return (Fp12)(z).String() }
func (z Cyclo6) IsEqual(x *Cyclo6) int    { return (Fp12)(z).IsEqual((*Fp12)(x)) }
func (z Cyclo6) IsIdentity() int          { i := &Fp12{}; i.SetOne(); return z.IsEqual((*Cyclo6)(i)) }
func (z *Cyclo6) Frob(x *Cyclo6)          { (*Fp12)(z).Frob((*Fp12)(x)) }
func (z *Cyclo6) Mul(x, y *Cyclo6)        { (*Fp12)(z).Mul((*Fp12)(x), (*Fp12)(y)) }
func (z *Cyclo6) Sqr(x *Cyclo6)           { (*Fp12)(z).Sqr((*Fp12)(x)) }
func (z *Cyclo6) Inv(x *Cyclo6)           { *z = *x; z[1].Neg() }
func (z *Cyclo6) exp(x *Cyclo6, n []byte) { (*Fp12)(z).Exp((*Fp12)(x), n) }

// PowToX computes z = x^paramX, where paramX is the parameter of the BLS curve.
func (z *Cyclo6) PowToX(x *Cyclo6) {
	t := new(Cyclo6)
	*t = *x
	const lenX = 64
	for i := lenX - 2; i >= 0; i-- {
		t.Sqr(t)
		// paramX is -2 ^ 63 - 2 ^ 62 - 2 ^ 60 - 2 ^ 57 - 2 ^ 48 - 2 ^ 16
		if (i == 62) || (i == 60) || (i == 57) || (i == 48) || (i == 16) {
			t.Mul(t, x)
		}
	}
	z.Inv(t)
}

// EasyExponentiation calculates g = f^(p^6-1)(p^2+1), where g becomes an
// element of the 6-th cyclotomic group.
func EasyExponentiation(g *Cyclo6, f *Fp12) {
	var t0, t1, p Fp12
	p.Frob(f)        // p = f^(p)
	p.Frob(&p)       // p = f^(p^2)
	t0.Mul(&p, f)    // t0 = f^(p^2 + 1)
	t1.Frob(&t0)     // t1 = f^(p^2 + 1)*(p)
	t1.Frob(&t1)     // t1 = f^(p^2 + 1)*(p^2)
	t1.Frob(&t1)     // t1 = f^(p^2 + 1)*(p^3)
	t1.Frob(&t1)     // t1 = f^(p^2 + 1)*(p^4)
	t1.Frob(&t1)     // t1 = f^(p^2 + 1)*(p^5)
	t1.Frob(&t1)     // t1 = f^(p^2 + 1)*(p^6)
	t0.Inv(&t0)      // t0 = f^-(p^2 + 1)
	t0.Mul(&t0, &t1) // t0 = f^(p^2 + 1)*(p^6 - 1)

	*g = (Cyclo6)(t0)
}

// HardExponentiation calculates u = g^(Cy_6(p)/r), where u is a root of unity.
func HardExponentiation(u *URoot, g *Cyclo6) {
	var t0, t1, _g, g3 Cyclo6
	var c, a0, a1, a2, a3 Cyclo6
	_g.Inv(g)        // _g = g^-1
	g3.Sqr(g)        // g3 = g^2
	g3.Mul(&g3, g)   // g3 = g^3
	t0.PowToX(g)     // t0 = g^x
	t0.Mul(&t0, &_g) // t0 = g^(x-1)
	t1.PowToX(&t0)   // t1 = g^(x-1)*x
	t0.Inv(&t0)      // t0 = g^-(x-1)
	a3.Mul(&t1, &t0) // a3 = g^(x-1)*(x-1)
	a2.Frob(&a3)     // a2 = a3*p
	a1.Frob(&a2)     // a1 = a2*p = a3*p^2
	t0.Inv(&a3)      // t0 = -a3
	a1.Mul(&a1, &t0) // a1 = a3*p^2-a3
	a0.Frob(&a1)     // a0 = a3*p^3-a3*p
	a0.Mul(&a0, &g3) // a0 = a3*p^3-a3*p+3

	c.PowToX(&a3)  // c = g^(a3*x)
	c.Mul(&c, &a2) // c = g^(a3*x+a2)
	c.PowToX(&c)   // c = g^(a3*x+a2)*x = g^(a3*x^2+a2*x)
	c.Mul(&c, &a1) // c = g^(a3*x^2+a2*x+a1)
	c.PowToX(&c)   // c = g^(a3*x^2+a2*x+a1)*x = g^(a3*x^3+a2*x^2+a1*x)
	c.Mul(&c, &a0) // c = g^(a3*x^3+a2*x^2+a1*x+a0)

	*u = (URoot)(c)
}
