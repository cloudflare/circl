package ff

import "fmt"

// Fp2Size is the length in bytes of an Fp2 element.
const Fp2Size = 2 * FpSize

type Fp2 [2]Fp

func (z Fp2) String() string { return fmt.Sprintf("0: %v\n1: %v", z[0], z[1]) }
func (z *Fp2) SetOne()       { z[0].SetOne(); z[1] = Fp{} }

// IsNegative returns 1 if z is lexicographically larger than -z; otherwise returns 0.
func (z Fp2) IsNegative() int    { return z[1].IsNegative() | (z[1].IsZero() & z[0].IsNegative()) }
func (z Fp2) IsZero() int        { return z.IsEqual(&Fp2{}) }
func (z Fp2) IsEqual(x *Fp2) int { return z[0].IsEqual(&x[0]) & z[1].IsEqual(&x[1]) }
func (z *Fp2) MulBeta()          { t := z[0]; z[0].Sub(&z[0], &z[1]); z[1].Add(&t, &z[1]) }
func (z *Fp2) Frob(x *Fp2)       { *z = *x; z.Cjg() }
func (z *Fp2) Cjg()              { z[1].Neg() }
func (z *Fp2) Neg()              { z[0].Neg(); z[1].Neg() }
func (z *Fp2) Add(x, y *Fp2)     { z[0].Add(&x[0], &y[0]); z[1].Add(&x[1], &y[1]) }
func (z *Fp2) Sub(x, y *Fp2)     { z[0].Sub(&x[0], &y[0]); z[1].Sub(&x[1], &y[1]) }
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

func (z Fp2) Sgn0() int {
	s0, s1 := z[0].Sgn0(), z[1].Sgn0()
	z0 := z[0].IsZero()
	return s0 | (z0 & s1)
}

func (z *Fp2) UnmarshalBinary(b []byte) error {
	if len(b) < Fp2Size {
		return errInputLength
	}
	return errFirst(
		z[1].UnmarshalBinary(b[:FpSize]),
		z[0].UnmarshalBinary(b[FpSize:2*FpSize]),
	)
}

func (z Fp2) MarshalBinary() (b []byte, e error) {
	var b0, b1 []byte
	if b1, e = z[1].MarshalBinary(); e == nil {
		if b0, e = z[0].MarshalBinary(); e == nil {
			return append(b1, b0...), e
		}
	}
	return
}

// SetString reconstructs a Fp2 element as s0+s1*i, where s0 and s1 are numeric
// strings from 0 to FpOrder-1.
func (z *Fp2) SetString(s0, s1 string) (err error) {
	if err = z[0].SetString(s0); err == nil {
		err = z[1].SetString(s1)
	}
	return
}

func (z *Fp2) CMov(x, y *Fp2, b int) {
	z[0].CMov(&x[0], &y[0], b)
	z[1].CMov(&x[1], &y[1], b)
}

// ExpVarTime calculates z=x^n, where n is the exponent in big-endian order.
func (z *Fp2) ExpVarTime(x *Fp2, n []byte) {
	zz := new(Fp2)
	zz.SetOne()
	N := 8 * len(n)
	for i := 0; i < N; i++ {
		zz.Sqr(zz)
		bit := 0x1 & (n[i/8] >> uint(7-i%8))
		if bit != 0 {
			zz.Mul(zz, x)
		}
	}
	*z = *zz
}

// Sqrt returns 1 and sets z=sqrt(x) only if x is a quadratic-residue; otherwise, returns 0 and z is unmodified.
func (z *Fp2) Sqrt(x *Fp2) int {
	// "Square-root for q = p^2 = 9 (mod 16)" Appendix I.3 of Hashing to elliptic curves.
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#appendix-I.3
	var t, tv1, tv2, tv3, tv4 Fp2
	tv1.ExpVarTime(x, fp2SqrtConst.c4[:])
	tv2.Mul(&fp2SqrtConst.c1, &tv1)
	tv3.Mul(&fp2SqrtConst.c2, &tv1)
	tv4.Mul(&fp2SqrtConst.c3, &tv1)

	t.Sqr(&tv1)
	e1 := t.IsEqual(x)
	z.CMov(z, &tv1, e1)

	t.Sqr(&tv2)
	e2 := t.IsEqual(x)
	z.CMov(z, &tv2, e2)

	t.Sqr(&tv3)
	e3 := t.IsEqual(x)
	z.CMov(z, &tv3, e3)

	t.Sqr(&tv4)
	e4 := t.IsEqual(x)
	z.CMov(z, &tv4, e4)

	return e1 | e2 | e3 | e4
}

var fp2SqrtConst = struct {
	// "Square-root for q = p^2 = 9 (mod 16)" Appendix I.3 of Hashing to elliptic curves.
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#appendix-I.3
	c1 Fp2      // c1 = sqrt( -1) = u
	c2 Fp2      // c2 = sqrt( c1)
	c3 Fp2      // c3 = sqrt(-c1)
	c4 [95]byte // c4 = (p^2 + 7) / 16 (big-endian)
}{
	c1: Fp2{ // (little-endian)
		Fp{fpMont{}},
		Fp{fpMont{0x760900000002fffd, 0xebf4000bc40c0002, 0x5f48985753c758ba, 0x77ce585370525745, 0x5c071a97a256ec6d, 0x15f65ec3fa80e493}},
	},
	c2: Fp2{ // (little-endian)
		Fp{fpMont{0x3e2f585da55c9ad1, 0x4294213d86c18183, 0x382844c88b623732, 0x92ad2afd19103e18, 0x1d794e4fac7cf0b9, 0x0bd592fc7d825ec8}},
		Fp{fpMont{0x7bcfa7a25aa30fda, 0xdc17dec12a927e7c, 0x2f088dd86b4ebef1, 0xd1ca2087da74d4a7, 0x2da2596696cebc1d, 0x0e2b7eedbbfd87d2}},
	},
	c3: Fp2{ // (little-endian)
		Fp{fpMont{0x7bcfa7a25aa30fda, 0xdc17dec12a927e7c, 0x2f088dd86b4ebef1, 0xd1ca2087da74d4a7, 0x2da2596696cebc1d, 0x0e2b7eedbbfd87d2}},
		Fp{fpMont{0x7bcfa7a25aa30fda, 0xdc17dec12a927e7c, 0x2f088dd86b4ebef1, 0xd1ca2087da74d4a7, 0x2da2596696cebc1d, 0x0e2b7eedbbfd87d2}},
	},
	c4: [95]byte{ // (big-endian)
		0x2a, 0x43, 0x7a, 0x4b, 0x8c, 0x35, 0xfc, 0x74, 0xbd, 0x27, 0x8e, 0xaa,
		0x22, 0xf2, 0x5e, 0x9e, 0x2d, 0xc9, 0x0e, 0x50, 0xe7, 0x04, 0x6b, 0x46,
		0x6e, 0x59, 0xe4, 0x93, 0x49, 0xe8, 0xbd, 0x05, 0x0a, 0x62, 0xcf, 0xd1,
		0x6d, 0xdc, 0xa6, 0xef, 0x53, 0x14, 0x93, 0x30, 0x97, 0x8e, 0xf0, 0x11,
		0xd6, 0x86, 0x19, 0xc8, 0x61, 0x85, 0xc7, 0xb2, 0x92, 0xe8, 0x5a, 0x87,
		0x09, 0x1a, 0x04, 0x96, 0x6b, 0xf9, 0x1e, 0xd3, 0xe7, 0x1b, 0x74, 0x31,
		0x62, 0xc3, 0x38, 0x36, 0x21, 0x13, 0xcf, 0xd7, 0xce, 0xd6, 0xb1, 0xd7,
		0x63, 0x82, 0xea, 0xb2, 0x6a, 0xa0, 0x00, 0x01, 0xc7, 0x18, 0xe4,
	},
}
