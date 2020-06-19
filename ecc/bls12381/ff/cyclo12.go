package ff

import "fmt"

// Cyclo12 represents an element of the 12-th cyclotomic group.
type Cyclo12 [2]Fp6

func (z Cyclo12) String() string           { return fmt.Sprintf("\n0: %v\n1: %v", z[0], z[1]) }
func (z *Cyclo12) SetOne()                 { z[0].SetOne(); z[1].SetZero() }
func (z *Cyclo12) Set(x *Cyclo12)          { z[0].Set(&x[0]); z[1].Set(&x[1]) }
func (z *Cyclo12) Inv(x *Cyclo12)          { z.Set(x); z[1].Neg() }
func (z *Cyclo12) IsZero() bool            { return z[0].IsZero() && z[1].IsZero() }
func (z *Cyclo12) IsEqual(x *Cyclo12) bool { return z[0].IsEqual(&x[0]) && z[1].IsEqual(&x[1]) }
func (z *Cyclo12) Frob(x *Cyclo12)         { z[0].Frob(&x[0]); z[1].Frob(&x[1]); z[1].Mul(&z[1], &frob12W1) }
func (z *Cyclo12) Add(x, y *Cyclo12)       { z[0].Add(&x[0], &y[0]); z[1].Add(&x[1], &y[1]) }
func (z *Cyclo12) Sub(x, y *Cyclo12)       { z[0].Sub(&x[0], &y[0]); z[1].Sub(&x[1], &y[1]) }
func (z *Cyclo12) Mul(x, y *Cyclo12) {
	var x0y0, x1y1, sx, sy, k Fp6
	x0y0.Mul(&x[0], &y[0])
	x1y1.Mul(&x[1], &y[1])
	sx.Add(&x[0], &x[1])
	sy.Add(&y[0], &y[1])
	k.Mul(&sx, &sy)
	z[1].Sub(&k, &x0y0)
	z[1].Sub(&z[1], &x1y1)
	x1y1.MulBeta()
	z[0].Add(&x0y0, &x1y1)
}
func (z *Cyclo12) Sqr(x *Cyclo12) {
	var x02, x12, k Fp6
	x02.Sqr(&x[0])
	x12.Sqr(&x[1])
	x12.MulBeta()
	k.Mul(&x[0], &x[1])
	z[0].Add(&x02, &x12)
	z[1].Add(&k, &k)
}
func (z *Cyclo12) Pow(x *Cyclo12) {
	var t Cyclo12
	t.Set(x)
	const lenX = 64
	for i := lenX - 2; i >= 0; i-- {
		t.Sqr(&t)
		// paramX is -2 ^ 63 - 2 ^ 62 - 2 ^ 60 - 2 ^ 57 - 2 ^ 48 - 2 ^ 16
		if (i == 62) || (i == 60) || (i == 57) || (i == 48) || (i == 16) {
			t.Mul(&t, x)
		}
	}
	z.Inv(&t)
}

// EasyExponentiation raises f^(p^6-1)(p^2+1) and returns an element in the
// 12-th cyclotomic group.
func EasyExponentiation(f *Fp12) *Cyclo12 {
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

	var g Cyclo12
	g[0].Set(&t0[0])
	g[1].Set(&t0[1])
	return &g
}
