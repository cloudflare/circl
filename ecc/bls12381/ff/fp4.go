package ff

import "fmt"

// Fp4Size is the size of an Fp4 element
const Fp4Size = 4 * FpSize

// Fp4 is obtained by adjoining t, the square root of u+1 to Fp2
type Fp4 [2]Fp2

func (z Fp4) String() string { return fmt.Sprintf("%s + ( %s )*t", z[0], z[1]) }

func (z *Fp4) SetOne() {
	z[0].SetOne()
	z[1] = Fp2{}
}

func (z *Fp4) IsZero() int {
	return z.IsEqual(&Fp4{})
}

func (z *Fp4) IsEqual(x *Fp4) int {
	return z[0].IsEqual(&x[0]) & z[1].IsEqual(&x[1])
}

func (z *Fp4) Neg() {
	z[0].Neg()
	z[1].Neg()
}

func (z *Fp4) Add(x *Fp4, y *Fp4) {
	z[0].Add(&x[0], &y[0])
	z[1].Add(&x[1], &y[1])
}

func (z *Fp4) Sub(x *Fp4, y *Fp4) {
	z[0].Sub(&x[0], &y[0])
	z[1].Sub(&x[1], &y[1])
}

func (z *Fp4) Mul(x *Fp4, y *Fp4) {
	var x0y0, x1y1, sx, sy, k Fp2
	x0y0.Mul(&x[0], &y[0])
	x1y1.Mul(&x[1], &y[1])
	sx.Add(&x[0], &x[1])
	sy.Add(&y[0], &y[1])
	k.Mul(&sx, &sy)
	k.Sub(&k, &x0y0)
	k.Sub(&k, &x1y1)
	// k is x0y1+x1y0 computed as (x0+x1)(y0+y1)-x0y0-x1y1
	z[1] = k
	// Multiply x1y1 by u+1
	z[0][1].Add(&x1y1[0], &x1y1[1])
	z[0][0].Sub(&x1y1[0], &x1y1[1])
	z[0].Add(&z[0], &x0y0)
}

func (z *Fp4) Sqr(x *Fp4) {
	var x0s, x1s, sx, k Fp2
	x0s.Sqr(&x[0])
	x1s.Sqr(&x[1])
	sx.Add(&x[0], &x[1])
	k.Sqr(&sx)
	k.Sub(&k, &x0s)
	k.Sub(&k, &x1s)

	z[1] = k
	// Multiplying x1s by u+1
	z[0][1].Add(&x1s[0], &x1s[1])
	z[0][0].Sub(&x1s[0], &x1s[1])
	z[0].Add(&z[0], &x0s)
}

func (z *Fp4) Inv(x *Fp4) {
	// Compute the inverse via conjugation
	var denom, x0sqr, x1sqr Fp2
	x0sqr.Sqr(&x[0])
	x1sqr.Sqr(&x[1])
	denom[1].Add(&x1sqr[0], &x1sqr[1])
	denom[0].Sub(&x1sqr[0], &x1sqr[1])
	denom.Sub(&x0sqr, &denom)
	denom.Inv(&denom)
	z[0] = x[0]
	z[1].Sub(&z[1], &x[1])
	z.mulSubfield(z, &denom)
}

func (z *Fp4) mulSubfield(x *Fp4, y *Fp2) {
	z[0].Mul(&x[0], y)
	z[1].Mul(&x[1], y)
}

func (z *Fp4) mulT(x *Fp4) {
	var t Fp4
	t[1] = x[0]
	t[0][1].Add(&x[1][0], &x[1][1])
	t[0][0].Sub(&x[1][0], &x[1][1])
	*z = t
}
