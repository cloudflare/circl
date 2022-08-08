package ff

import (
	"io"

	"github.com/cloudflare/circl/internal/conv"
)

// FpSize is the length in bytes of an Fp element.
const FpSize = 48

// fpMont represents an element in the Montgomery domain (little-endian).
type fpMont = [FpSize / 8]uint64

// fpRaw represents an element in the integers domain (little-endian).
type fpRaw = [FpSize / 8]uint64

// Fp represents prime field elements as positive integers less than FpOrder.
type Fp struct{ i fpMont }

func (z Fp) String() string            { x := z.fromMont(); return conv.Uint64Le2Hex(x[:]) }
func (z *Fp) SetUint64(n uint64)       { z.toMont(&fpRaw{n}) }
func (z *Fp) SetOne()                  { z.SetUint64(1) }
func (z *Fp) Random(r io.Reader) error { return randomInt(z.i[:], r, fpOrder[:]) }

// IsNegative returns 0 if the least absolute residue for z is in [0,(p-1)/2],
// and 1 otherwise. Equivalently, this function returns 1 if z is
// lexicographically larger than -z.
func (z Fp) IsNegative() int {
	b, _ := z.MarshalBinary()
	return 1 - isLessThan(b, fpOrderPlus1Div2[:])
}

// IsZero returns 1 if z == 0 and 0 otherwise.
func (z Fp) IsZero() int { return ctUint64Eq(z.i[:], (&fpMont{})[:]) }

// IsEqual returns 1 if z == x and 0 otherwise.
func (z Fp) IsEqual(x *Fp) int     { return ctUint64Eq(z.i[:], x.i[:]) }
func (z *Fp) Neg()                 { fiatFpMontSub(&z.i, &fpMont{}, &z.i) }
func (z *Fp) Add(x, y *Fp)         { fiatFpMontAdd(&z.i, &x.i, &y.i) }
func (z *Fp) Sub(x, y *Fp)         { fiatFpMontSub(&z.i, &x.i, &y.i) }
func (z *Fp) Mul(x, y *Fp)         { fiatFpMontMul(&z.i, &x.i, &y.i) }
func (z *Fp) Sqr(x *Fp)            { fiatFpMontSquare(&z.i, &x.i) }
func (z *Fp) toMont(in *fpRaw)     { fiatFpMontMul(&z.i, in, &fpRSquare) }
func (z Fp) fromMont() (out fpRaw) { fiatFpMontMul(&out, &z.i, &fpMont{1}); return }
func (z Fp) Sgn0() int             { return int(z.fromMont()[0]) & 1 }

// Sqrt returns 1 and sets z=sqrt(x) only if x is a quadratic-residue; otherwise, returns 0 and z is unmodified.
func (z *Fp) Sqrt(x *Fp) int {
	var y, y2 Fp
	y.ExpVarTime(x, fpOrderPlus1Div4[:])
	y2.Sqr(&y)
	isQR := y2.IsEqual(x)
	z.CMov(z, &y, isQR)
	return isQR
}

// CMov sets z=x if b == 0 and z=y if b == 1. Its behavior is undefined if b takes any other value.
func (z *Fp) CMov(x, y *Fp, b int) {
	mask := -uint64(b & 0x1)
	for i := 0; i < FpSize/8; i++ {
		z.i[i] = (x.i[i] &^ mask) | (y.i[i] & mask)
	}
}

// FpOrder is the order of the base field for towering returned as a big-endian slice.
//
//	FpOrder = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab.
func FpOrder() []byte { o := fpOrder; return o[:] }

// ExpVarTime calculates z=x^n, where n is the exponent in big-endian order.
func (z *Fp) ExpVarTime(x *Fp, n []byte) {
	zz := new(Fp)
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

// SetBytes assigns to z the number modulo FpOrder stored in the slice
// (in big-endian order).
func (z *Fp) SetBytes(data []byte) {
	in64 := setBytesUnbounded(data, fpOrder[:])
	s := &fpRaw{}
	copy(s[:], in64[:FpSize/8])
	z.toMont(s)
}

// MarshalBinary returns a slice of FpSize bytes that contains the minimal
// residue of z such that 0 <= z < FpOrder (in big-endian order).
func (z *Fp) MarshalBinary() ([]byte, error) {
	x := z.fromMont()
	return conv.Uint64Le2BytesBe(x[:]), nil
}

// UnmarshalBinary reconstructs a Fp from a slice that must have at least
// FpSize bytes and contain a number (in big-endian order) from 0
// to FpOrder-1.
func (z *Fp) UnmarshalBinary(b []byte) error {
	if len(b) < FpSize {
		return errInputLength
	}
	in64, err := setBytesBounded(b[:FpSize], fpOrder[:])
	if err == nil {
		s := &fpRaw{}
		copy(s[:], in64[:FpSize/8])
		z.toMont(s)
	}
	return err
}

// SetString reconstructs a Fp from a numeric string from 0 to FpOrder-1.
func (z *Fp) SetString(s string) error {
	in64, err := setString(s, fpOrder[:])
	if err == nil {
		s := &fpRaw{}
		copy(s[:], in64[:FpSize/8])
		z.toMont(s)
	}
	return err
}

func fiatFpMontCmovznzU64(z *uint64, b, x, y uint64) { cselectU64(z, b, x, y) }

func (z *Fp) Inv(x *Fp) {
	// Addition chain found using mmcloughlin/addchain: v0.3.0
	// McLoughlin, Michael Ben. (2021). https://doi.org/10.5281/zenodo.4758226
	var i2, i4, i8, i9, i11, i13, i17, i20, i25, i26, i52, i54, i55, i77, i79,
		i86, i93, i103, i105, i119, i123, i137, i149, i151, i169, i177, i191,
		i195, i208, i215, i225, i229, i235, i245, i255 Fp

	i2.Sqr(x)
	i4.Sqr(&i2)
	i8.Sqr(&i4)
	i9.Mul(&i8, x)
	i11.Mul(&i9, &i2)
	i13.Mul(&i11, &i2)
	i17.Mul(&i13, &i4)
	i20.Mul(&i11, &i9)
	i25.Mul(&i17, &i8)
	i26.Mul(&i25, x)
	i52.Sqr(&i26)
	i54.Mul(&i52, &i2)
	i55.Mul(&i54, x)
	i77.Mul(&i52, &i25)
	i79.Mul(&i77, &i2)
	i86.Mul(&i77, &i8)
	i93.Mul(&i86, &i8)
	i103.Mul(&i77, &i26)
	i105.Mul(&i103, &i2)
	i119.Mul(&i93, &i26)
	i123.Mul(&i119, &i4)
	i137.Mul(&i86, &i52)
	i149.Mul(&i123, &i26)
	i151.Mul(&i149, &i2)
	i169.Mul(&i149, &i20)
	i177.Mul(&i169, &i8)
	i191.Mul(&i137, &i54)
	i195.Mul(&i191, &i4)
	i208.Mul(&i195, &i13)
	i215.Mul(&i195, &i20)
	i225.Mul(&i208, &i17)
	i229.Mul(&i225, &i4)
	i235.Mul(&i215, &i20)
	i245.Mul(&i225, &i20)
	i255.Mul(&i235, &i20)
	z.Mul(&i225, &i191)

	for _, s := range []struct {
		l int
		x *Fp
	}{
		{8, &i17},
		{11, &i245},
		{11, &i229},
		{8, &i255},
		{7, &i77},
		{9, &i105},
		{10, &i177},
		{7, &i93},
		{9, &i123},
		{6, &i25},
		{11, &i105},
		{9, &i235},
		{10, &i215},
		{6, &i25},
		{10, &i119},
		{9, &i151},
		{11, &i79},
		{10, &i225},
		{9, &i137},
		{9, &i191},
		{8, &i103},
		{10, &i195},
		{9, &i149},
		{12, &i123},
		{5, &i11},
		{11, &i123},
		{7, &i9},
		{13, &i245},
		{9, &i191},
		{8, &i255},
		{8, &i235},
		{11, &i169},
		{8, &i255},
		{8, &i255},
		{6, &i55},
		{10, &i255},
		{9, &i255},
		{8, &i255},
		{8, &i255},
		{8, &i255},
		{7, &i86},
		{9, &i169},
	} {
		for i := 0; i < s.l; i++ {
			z.Sqr(z)
		}
		z.Mul(z, s.x)
	}
}

var (
	// fpOrder is the order of the Fp field (big-endian).
	fpOrder = [FpSize]byte{
		0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a,
		0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b, 0xac, 0xd7,
		0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf,
		0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0, 0xf6, 0x24,
		0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff,
		0xb9, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xab,
	}
	// fpOrderPlus1Div2 is the half of (fpOrder plus one) used for lexicographically order (big-endian).
	fpOrderPlus1Div2 = [FpSize]byte{
		0x0d, 0x00, 0x88, 0xf5, 0x1c, 0xbf, 0xf3, 0x4d,
		0x25, 0x8d, 0xd3, 0xdb, 0x21, 0xa5, 0xd6, 0x6b,
		0xb2, 0x3b, 0xa5, 0xc2, 0x79, 0xc2, 0x89, 0x5f,
		0xb3, 0x98, 0x69, 0x50, 0x7b, 0x58, 0x7b, 0x12,
		0x0f, 0x55, 0xff, 0xff, 0x58, 0xa9, 0xff, 0xff,
		0xdc, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xd5, 0x56,
	}
	// fpOrderPlus1Div4 is (fpOrder plus one) divided by four used for square-roots (big-endian).
	fpOrderPlus1Div4 = [FpSize]byte{
		0x06, 0x80, 0x44, 0x7a, 0x8e, 0x5f, 0xf9, 0xa6,
		0x92, 0xc6, 0xe9, 0xed, 0x90, 0xd2, 0xeb, 0x35,
		0xd9, 0x1d, 0xd2, 0xe1, 0x3c, 0xe1, 0x44, 0xaf,
		0xd9, 0xcc, 0x34, 0xa8, 0x3d, 0xac, 0x3d, 0x89,
		0x07, 0xaa, 0xff, 0xff, 0xac, 0x54, 0xff, 0xff,
		0xee, 0x7f, 0xbf, 0xff, 0xff, 0xff, 0xea, 0xab,
	}
	// fpRSquare is R^2 mod fpOrder, where R=2^384 (little-endian).
	fpRSquare = fpMont{
		0xf4df1f341c341746, 0x0a76e6a609d104f1,
		0x8de5476c4c95b6d5, 0x67eb88a9939d83c0,
		0x9a793e85b519952d, 0x11988fe592cae3aa,
	}
)
