package ff

import "fmt"

// Fp12Size is the length in bytes of a Fp12 element.
const Fp12Size = 2 * Fp6Size

// Fp12 represents an element of the field Fp12 = Fp6[w]/(w^2-v)., where v in Fp6.
type Fp12 [2]Fp6

func (z Fp12) String() string        { return fmt.Sprintf("\n0: %v\n1: %v", z[0], z[1]) }
func (z *Fp12) Set(x *Fp12)          { z[0].Set(&x[0]); z[1].Set(&x[1]) }
func (z *Fp12) SetBytes(b []byte)    { z[0].SetBytes(b[:Fp6Size]); z[1].SetBytes(b[Fp6Size : 2*Fp6Size]) }
func (z *Fp12) Bytes() []byte        { return append(z[0].Bytes(), z[1].Bytes()...) }
func (z *Fp12) SetZero()             { z[0].SetZero(); z[1].SetZero() }
func (z *Fp12) SetOne()              { z[0].SetOne(); z[1].SetZero() }
func (z *Fp12) IsZero() bool         { return z[0].IsZero() && z[1].IsZero() }
func (z *Fp12) IsEqual(x *Fp12) bool { return z[0].IsEqual(&x[0]) && z[1].IsEqual(&x[1]) }
func (z *Fp12) MulBeta()             { var t Fp6; t.Set(&z[0]); z[0].Sub(&z[0], &z[1]); z[1].Add(&t, &z[1]) }
func (z *Fp12) Frob(x *Fp12)         { z[0].Frob(&x[0]); z[1].Frob(&x[1]); z[1].Mul(&z[1], &frob12W1) }
func (z *Fp12) Cjg()                 { z[1].Neg() }
func (z *Fp12) Neg()                 { z[0].Neg(); z[1].Neg() }
func (z *Fp12) Add(x, y *Fp12)       { z[0].Add(&x[0], &y[0]); z[1].Add(&x[1], &y[1]) }
func (z *Fp12) Sub(x, y *Fp12)       { z[0].Sub(&x[0], &y[0]); z[1].Sub(&x[1], &y[1]) }
func (z *Fp12) Mul(x, y *Fp12) {
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
func (z *Fp12) Sqr(x *Fp12) {
	var x02, x12, k Fp6
	x02.Sqr(&x[0])
	x12.Sqr(&x[1])
	x12.MulBeta()
	k.Mul(&x[0], &x[1])
	z[0].Add(&x02, &x12)
	z[1].Add(&k, &k)
}
func (z *Fp12) Inv(x *Fp12) {
	var x02, x12, den Fp6
	x02.Sqr(&x[0])
	x12.Sqr(&x[1])
	x12.MulBeta()
	den.Sub(&x02, &x12)
	den.Inv(&den)
	z[0].Mul(&x[0], &den)
	z[1].Mul(&x[1], &den)
	z[1].Neg()
}
func (z *Fp12) Exp(x *Fp12, n []byte) {
	z.SetOne()
	for i := 8*len(n) - 1; i >= 0; i-- {
		z.Sqr(z)
		bit := 0x1 & (n[i/8] >> uint(i%8))
		if bit != 0 {
			z.Mul(z, x)
		}
	}
}
