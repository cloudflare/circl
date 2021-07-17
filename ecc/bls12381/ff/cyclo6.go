package ff

// Cyclo6 represents an element of the 6th cyclotomic group.
//
// References: https://eprint.iacr.org/2009/565
type Cyclo6 Fp12

func (z Cyclo6) String() string           { return (Fp12)(z).String() }
func (z *Cyclo6) Set(x *Cyclo6)           { (*Fp12)(z).Set((*Fp12)(x)) }
func (z Cyclo6) IsEqual(x *Cyclo6) bool   { return (Fp12)(z).IsEqual((*Fp12)(x)) }
func (z *Cyclo6) Frob(x *Cyclo6)          { (*Fp12)(z).Frob((*Fp12)(x)) }
func (z *Cyclo6) Mul(x, y *Cyclo6)        { (*Fp12)(z).Mul((*Fp12)(x), (*Fp12)(y)) }
func (z *Cyclo6) Sqr(x *Cyclo6)           { (*Fp12)(z).Sqr((*Fp12)(x)) }
func (z *Cyclo6) Exp(x *Cyclo6, n []byte) { (*Fp12)(z).Exp((*Fp12)(x), n) }

func (z *Cyclo6) Inv(x *Cyclo6)   { z.Set(x); z[1].Neg() }
func (z *Cyclo6) SetIdentity()    { (*Fp12)(z).SetOne() }
func (z Cyclo6) IsIdentity() bool { i := &Cyclo6{}; i.SetIdentity(); return z.IsEqual(i) }

// PowToX computes z = x^paramX, where paramX is the parameter of the BLS curve.
func (z *Cyclo6) PowToX(x *Cyclo6) {
	t := new(Cyclo6)
	t.Set(x)
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

// EasyExponentiation raises f^(p^6-1)(p^2+1) and returns an element in the
// 6-th cyclotomic group.
func EasyExponentiation(f *Fp12) *Cyclo6 {
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

	return (*Cyclo6)(&t0)
}
