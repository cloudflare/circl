package ff

import (
	"crypto/subtle"
	"fmt"
)

// Fp12Size is the length in bytes of an Fp12 element.
const Fp12Size = 2 * Fp6Size

// Fp12 represents an element of the field Fp12 = Fp6[w]/(w^2-v)., where v in Fp6.
type Fp12 [2]Fp6

func (z Fp12) String() string      { return fmt.Sprintf("0: %v\n1: %v", z[0], z[1]) }
func (z *Fp12) SetOne()            { z[0].SetOne(); z[1] = Fp6{} }
func (z Fp12) IsZero() int         { return z.IsEqual(&Fp12{}) }
func (z Fp12) IsEqual(x *Fp12) int { return z[0].IsEqual(&x[0]) & z[1].IsEqual(&x[1]) }
func (z *Fp12) MulBeta()           { t := z[0]; z[0].Sub(&z[0], &z[1]); z[1].Add(&t, &z[1]) }
func (z *Fp12) Frob(x *Fp12)       { z[0].Frob(&x[0]); z[1].Frob(&x[1]); z[1].Mul(&z[1], &Fp6{frob12W1}) }
func (z *Fp12) Cjg()               { z[1].Neg() }
func (z *Fp12) Neg()               { z[0].Neg(); z[1].Neg() }
func (z *Fp12) Add(x, y *Fp12)     { z[0].Add(&x[0], &y[0]); z[1].Add(&x[1], &y[1]) }
func (z *Fp12) Sub(x, y *Fp12)     { z[0].Sub(&x[0], &y[0]); z[1].Sub(&x[1], &y[1]) }
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

func (z *Fp12) CMov(x, y *Fp12, b int) {
	z[0].CMov(&x[0], &y[0], b)
	z[1].CMov(&x[1], &y[1], b)
}

// Exp calculates z=x^n, where n is the exponent in big-endian order.
func (z *Fp12) Exp(x *Fp12, n []byte) {
	zz := new(Fp12)
	zz.SetOne()
	T := new(Fp12)
	var mults [16]Fp12
	mults[0].SetOne()
	mults[1] = *x
	for i := 1; i < 8; i++ {
		mults[2*i] = mults[i]
		mults[2*i].Sqr(&mults[2*i])
		mults[2*i+1].Mul(&mults[2*i], x)
	}
	N := 8 * len(n)
	for i := 0; i < N; i += 4 {
		zz.Sqr(zz)
		zz.Sqr(zz)
		zz.Sqr(zz)
		zz.Sqr(zz)
		idx := 0xf & (n[i/8] >> uint(4-i%8))
		for j := 0; j < 16; j++ {
			T.CMov(T, &mults[j], subtle.ConstantTimeByteEq(idx, uint8(j)))
		}
		zz.Mul(zz, T)
	}
	*z = *zz
}

func (z *Fp12) UnmarshalBinary(b []byte) error {
	if len(b) < Fp12Size {
		return errInputLength
	}
	return errFirst(
		z[1].UnmarshalBinary(b[:Fp6Size]),
		z[0].UnmarshalBinary(b[Fp6Size:2*Fp6Size]),
	)
}

func (z Fp12) MarshalBinary() (b []byte, e error) {
	var b0, b1 []byte
	if b1, e = z[1].MarshalBinary(); e == nil {
		if b0, e = z[0].MarshalBinary(); e == nil {
			return append(b1, b0...), e
		}
	}
	return
}

// frob12W1 is Fp2 = [toMont(frob12W1_0), toMont(frob12W1_1) ], where
//
//	frob12W1_0 = 0x1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8
//	frob12W1_1 = 0xfc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3
var frob12W1 = Fp2{
	Fp{fpMont{ // (little-endian)
		0x07089552b319d465, 0xc6695f92b50a8313, 0x97e83cccd117228f,
		0xa35baecab2dc29ee, 0x1ce393ea5daace4d, 0x08f2220fb0fb66eb,
	}},
	Fp{fpMont{ // (little-endian)
		0xb2f66aad4ce5d646, 0x5842a06bfc497cec, 0xcf4895d42599d394,
		0xc11b9cba40a8e8d0, 0x2e3813cbe5a0de89, 0x110eefda88847faf,
	}},
}
