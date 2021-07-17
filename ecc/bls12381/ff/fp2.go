package ff

import "fmt"

// Fp2Size is the length in bytes of an Fp2 element.
const Fp2Size = 2 * FpSize

type Fp2 [2]Fp

func (z Fp2) String() string { return fmt.Sprintf("0: %v\n 1: %v", z[0], z[1]) }
func (z *Fp2) Set(x *Fp2)    { z[0].Set(&x[0]); z[1].Set(&x[1]) }
func (z *Fp2) SetBytes(b []byte) error {
	return errSum(z[0].SetBytes(b[:FpSize]), z[1].SetBytes(b[FpSize:2*FpSize]))
}
func (z Fp2) Bytes() []byte       { return append(z[0].Bytes(), z[1].Bytes()...) }
func (z *Fp2) SetOne()            { z[0].SetOne(); z[1] = Fp{} }
func (z Fp2) IsZero() bool        { return z.IsEqual(&Fp2{}) }
func (z Fp2) IsEqual(x *Fp2) bool { return z[0].IsEqual(&x[0]) && z[1].IsEqual(&x[1]) }
func (z *Fp2) MulBeta()           { var t Fp; t.Set(&z[0]); z[0].Sub(&z[0], &z[1]); z[1].Add(&t, &z[1]) }
func (z *Fp2) Frob(x *Fp2)        { z.Set(x); z.Cjg() }
func (z *Fp2) Cjg()               { z[1].Neg() }
func (z *Fp2) Neg()               { z[0].Neg(); z[1].Neg() }
func (z *Fp2) Add(x, y *Fp2)      { z[0].Add(&x[0], &y[0]); z[1].Add(&x[1], &y[1]) }
func (z *Fp2) Sub(x, y *Fp2)      { z[0].Sub(&x[0], &y[0]); z[1].Sub(&x[1], &y[1]) }
func (z *Fp2) Mul(x, y *Fp2) {
	var x0y0, x1y1, sx, sy, k Fp
	x0y0.Mul(&x[0], &y[0])
	x1y1.Mul(&x[1], &y[1])
	sx.Add(&x[0], &x[1])
	sy.Add(&y[0], &y[1])
	k.Mul(&sx, &sy)
	z[0].Sub(&x0y0, &x1y1)
	z[1].Sub(&k, &x0y0)
	z[1].Sub(&z[1], &x1y1)
}

func (z *Fp2) Sqr(x *Fp2) {
	var x02, x12, k Fp
	x02.Sqr(&x[0])
	x12.Sqr(&x[1])
	k.Mul(&x[0], &x[1])
	z[0].Sub(&x02, &x12)
	z[1].Add(&k, &k)
}

func (z *Fp2) Inv(x *Fp2) {
	var x02, x12, den Fp
	x02.Sqr(&x[0])
	x12.Sqr(&x[1])
	den.Add(&x02, &x12)
	den.Inv(&den)
	z[0].Mul(&x[0], &den)
	z[1].Mul(&x[1], &den)
	z[1].Neg()
}
