package ff

import "fmt"

// Fp6Size is the length in bytes of an Fp6 element.
const Fp6Size = 3 * Fp2Size

type Fp6 [3]Fp2

func (z Fp6) String() string { return fmt.Sprintf("\n0: %v\n1: %v\n2: %v", z[0], z[1], z[2]) }
func (z *Fp6) SetOne()       { z[0].SetOne(); z[1] = Fp2{}; z[2] = Fp2{} }
func (z Fp6) IsZero() int    { return z.IsEqual(&Fp6{}) }
func (z Fp6) IsEqual(x *Fp6) int {
	return z[0].IsEqual(&x[0]) & z[1].IsEqual(&x[1]) & z[2].IsEqual(&x[2])
}
func (z *Fp6) Neg()          { z[0].Neg(); z[1].Neg(); z[2].Neg() }
func (z *Fp6) Add(x, y *Fp6) { z[0].Add(&x[0], &y[0]); z[1].Add(&x[1], &y[1]); z[2].Add(&x[2], &y[2]) }
func (z *Fp6) Sub(x, y *Fp6) { z[0].Sub(&x[0], &y[0]); z[1].Sub(&x[1], &y[1]); z[2].Sub(&x[2], &y[2]) }
func (z *Fp6) MulBeta() {
	t := z[2]
	t.MulBeta()
	z[2] = z[1]
	z[1] = z[0]
	z[0] = t
}

func (z *Fp6) Mul(x, y *Fp6) {
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
	aLM, aLH, aMH := &Fp2{}, &Fp2{}, &Fp2{}
	bLM, bLH, bMH := &Fp2{}, &Fp2{}, &Fp2{}
	aLM.Add(aL, aM)
	aLH.Add(aL, aH)
	aMH.Add(aM, aH)
	bLM.Add(bL, bM)
	bLH.Add(bL, bH)
	bMH.Add(bM, bH)

	c0, c1, c2 := &Fp2{}, &Fp2{}, &Fp2{}
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

func (z *Fp6) Sqr(x *Fp6) {
	//  z = x^2 mod (v^3-B)
	// z0 = B(2x1*x2) + x0^2
	// z1 = B(x2^2) + 2x0*x1
	// z2 = 2x0*x2 + x1^2

	aL, aM, aH := &x[0], &x[1], &x[2]
	c0, c2, c4 := &z[0], &z[1], &z[2]
	c3, c5, tt := &Fp2{}, &Fp2{}, &Fp2{}
	tt.Add(aL, aH)
	tt.Sub(tt, aM)

	c3.Mul(aL, aM)
	c5.Mul(aM, aH)
	c0.Sqr(aL)
	c2.Sqr(aH)
	c4.Sqr(tt)

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

func (z *Fp6) Inv(x *Fp6) {
	aL, aM, aH := &x[0], &x[1], &x[2]
	c0, c1, c2 := &Fp2{}, &Fp2{}, &Fp2{}
	t0, t1, t2 := &Fp2{}, &Fp2{}, &Fp2{}
	c0.Sqr(aL)
	c1.Sqr(aH)
	c2.Sqr(aM)
	t0.Mul(aM, aH)
	t1.Mul(aL, aM)
	t2.Mul(aL, aH)
	t0.MulBeta()
	c0.Sub(c0, t0) // c0 = aL^2 - B(aM*AH)
	c1.MulBeta()
	c1.Sub(c1, t1) // c1 = B(aH^2) - aL*AM
	c2.Sub(c2, t2) // c1 = aM^2 - aL*AH

	t0.Mul(aM, c2)
	t1.Mul(aH, c1)
	t2.Mul(aL, c0)
	t0.Add(t0, t1)
	t0.MulBeta()
	t0.Add(t0, t2)
	t0.Inv(t0)       // den = B(aL*c2 + aM*c1) + aLc0
	z[0].Mul(c0, t0) // z0 = c0/den
	z[1].Mul(c1, t0) // z1 = c1/den
	z[2].Mul(c2, t0) // z2 = c2/den
}

func (z *Fp6) Frob(x *Fp6) {
	z[0].Frob(&x[0])
	z[1].Frob(&x[1])
	z[2].Frob(&x[2])
	z[1].Mul(&z[1], &Fp2{Fp{}, frob6V1})
	z[2].Mul(&z[2], &Fp2{frob6V2, Fp{}})
}

func (z *Fp6) CMov(x, y *Fp6, b int) {
	z[0].CMov(&x[0], &y[0], b)
	z[1].CMov(&x[1], &y[1], b)
	z[2].CMov(&x[2], &y[2], b)
}

func (z Fp6) MarshalBinary() (b []byte, e error) {
	var b0, b1, b2 []byte
	if b2, e = z[2].MarshalBinary(); e == nil {
		if b1, e = z[1].MarshalBinary(); e == nil {
			if b0, e = z[0].MarshalBinary(); e == nil {
				return append(append(b2, b1...), b0...), e
			}
		}
	}
	return
}

func (z *Fp6) UnmarshalBinary(b []byte) error {
	if len(b) < Fp6Size {
		return errInputLength
	}
	return errFirst(
		z[2].UnmarshalBinary(b[0*Fp2Size:1*Fp2Size]),
		z[1].UnmarshalBinary(b[1*Fp2Size:2*Fp2Size]),
		z[0].UnmarshalBinary(b[2*Fp2Size:3*Fp2Size]),
	)
}

var (
	// frob6V1 is toMont(v) = 2**384 * v mod fpPrime, where
	// v = 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac
	frob6V1 = Fp{fpMont{
		0xcd03c9e48671f071, 0x5dab22461fcda5d2, 0x587042afd3851b95,
		0x8eb60ebe01bacb9e, 0x03f97d6e83d050d2, 0x18f0206554638741,
	}}

	// frob6V2 is toMont(v) = 2**384 * v mod fpPrime, where
	// v = 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad
	frob6V2 = Fp{fpMont{
		0x890dc9e4867545c3, 0x2af322533285a5d5, 0x50880866309b7e2c,
		0xa20d1b8c7e881024, 0x14e4f04fe2db9068, 0x14e56d3f1564853a,
	}}
)
