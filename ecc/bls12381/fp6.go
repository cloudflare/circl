package bls12381

import "fmt"

type fp6 [3]fp2

func (z fp6) String() string { return fmt.Sprintf("%v\n+v*%v\n+v^2*%v", z[0], z[1], z[2]) }
func (z *fp6) Set(x *fp6)    { z[0].Set(&x[0]); z[1].Set(&x[1]); z[2].Set(&x[2]) }
func (z *fp6) SetZero()      { z[0].SetZero(); z[1].SetZero(); z[2].SetZero() }
func (z *fp6) SetOne()       { z[0].SetOne(); z[1].SetZero(); z[2].SetZero() }
func (z *fp6) IsZero() bool  { return z[0].IsZero() && z[1].IsZero() && z[2].IsZero() }
func (z *fp6) IsEqual(x *fp6) bool {
	return z[0].IsEqual(&x[0]) && z[1].IsEqual(&x[1]) && z[2].IsEqual(&x[2])
}
func (z *fp6) Neg()          { z[0].Neg(); z[1].Neg(); z[2].Neg() }
func (z *fp6) Add(x, y *fp6) { z[0].Add(&x[0], &y[0]); z[1].Add(&x[1], &y[1]); z[2].Add(&x[2], &y[2]) }
func (z *fp6) Sub(x, y *fp6) { z[0].Sub(&x[0], &y[0]); z[1].Sub(&x[1], &y[1]); z[2].Sub(&x[2], &y[2]) }
func (z *fp6) Mul(x, y *fp6) {
	// https://ia.cr/2006/224 (Sec3.1)
	//  z = x*y mod (v^3-B)
	// | v^4 | v^3 ||  v^2  |  v^1  |  v^0  |
	// |-----|-----||-------|-------|-------|
	// |     |     ||  -c2  |  -c1  |  +c0  |
	// |     | -c2 ||  +c1  |  -c0  |       |
	// | +c2 | -c1 ||  -c0  |       |       |
	// |     | +c5 ||  +c4  |  +c3  |       |
	// |-----|-----||-------|-------|-------|
	// |     |     ||       | B(+c2)| B(-c2)|
	// |     |     ||       |       | B(-c1)|
	// |     |     ||       |       | B(+c5)|

	aL, aM, aH := &x[0], &x[1], &x[2]
	bL, bM, bH := &y[0], &y[1], &y[2]
	aLM, aLH, aMH := &fp2{}, &fp2{}, &fp2{}
	bLM, bLH, bMH := &fp2{}, &fp2{}, &fp2{}
	aLM.Add(aL, aM)
	aLH.Add(aL, aH)
	aMH.Add(aM, aH)
	bLM.Add(bL, bM)
	bLH.Add(bL, bH)
	bMH.Add(bM, bH)

	c0, c1, c2 := aLM, aLH, aMH
	c5, c3, c4 := &z[0], &z[1], &z[2]
	c0.Mul(aL, bL)
	c1.Mul(aM, bM)
	c2.Mul(aH, bH)
	c3.Mul(aLM, bLM)
	c4.Mul(aLH, bLH)
	c5.Mul(aMH, bMH)

	z[2].Add(c4, c1)    // c4+c1
	z[2].Sub(&z[2], c0) // c4+c1-c0
	z[2].Sub(&z[2], c2) // z2 = c4+c1-c0-c2
	c2.MulBeta()        // Bc2
	c2.Sub(c2, c0)      // Bc2-c0
	z[1].Sub(c3, c1)    // c3-c1
	z[1].Add(&z[1], c2) // z1 = Bc2-c0+c3-c1
	z[0].Sub(c5, c1)    // c5-c1
	z[0].MulBeta()      // B(c5-c1)
	z[0].Sub(&z[0], c2) // z0 = B(c5-c1)-Bc2+c0 = B(c5-c1-c2)+c0
}
func (z *fp6) Sqr(x *fp6) {
	//  z = x^2 mod (v^3-B)
	// z0 = B(2x1*x2) + x0^2
	// z1 = B(x2^2) + 2x0*x1
	// z2 = 2x0*x2 + x1^2

	aL, aM, aH := &x[0], &x[1], &x[2]
	c0, c2, c4 := &z[0], &z[1], &z[2]
	c3, c5, tt := &fp2{}, &fp2{}, &fp2{}
	tt.Add(aL, aH)
	tt.Sub(tt, aM)

	c0.Sqr(aL)
	c2.Sqr(aH)
	c3.Mul(aL, aM)
	c4.Sqr(tt)
	c5.Mul(aM, aH)

	c5.Add(c5, c5)      // 2c5
	c3.Add(c3, c3)      // 2c3
	tt.Add(c3, c5)      // 2c3+2c5
	z[2].Add(tt, c4)    // 2c3+2c5+c4
	z[2].Sub(&z[2], c0) // 2c3+2c5+c4-c0
	z[2].Sub(&z[2], c2) // z2 = 2c3+2c5+c4-c0-c2
	c5.MulBeta()        // B(2c5)
	z[0].Add(c5, c0)    // z0 = B(2c5)+c0
	c2.MulBeta()        // B(c2)
	z[1].Add(c2, c3)    // z1 = B(c2)+2c3
}
func (z *fp6) Inv(x *fp6) {
	aL, aM, aH := &x[0], &x[1], &x[2]
	c0, c1, c2 := &z[0], &z[1], &z[2]
	t0, t1, t2 := &fp2{}, &fp2{}, &fp2{}
	c0.Sqr(aL)
	c1.Sqr(aH)
	c2.Sqr(aM)
	t0.Mul(aM, aH)
	t1.Mul(aL, aM)
	t2.Mul(aL, aH)
	t2.MulBeta()
	c0.Sub(c0, t0)
	c1.MulBeta()
	c1.Sub(c1, t1)
	c2.Sub(c2, t2)

	t0.Mul(aM, c2)
	t1.Mul(aH, c1)
	t2.Mul(aL, c0)
	t0.Add(t0, t1)
	t0.MulBeta()
	t0.Add(t0, t2)
	t0.Inv(t0)
	z[0].Mul(c0, t0)
	z[1].Mul(c1, t0)
	z[2].Mul(c2, t0)
}
func (z *fp6) Frob() {
	z[0].Frob()
	z[1].Frob()
	z[2].Frob()
	z[1].Mul(&z[1], &fp2{fp{}, fp{}})
	z[2].Mul(&z[2], &fp2{fp{}, fp{}})
}
