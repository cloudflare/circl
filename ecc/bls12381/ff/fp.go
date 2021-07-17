package ff

import (
	"io"

	"github.com/cloudflare/circl/internal/conv"
)

// FpSize is the length in bytes of an Fp element.
const FpSize = 48

// fpMont represents an element in Montgomery domain.
type fpMont = [FpSize / 8]uint64

// fpRaw represents an element in binary format.
type fpRaw = [FpSize / 8]uint64

// Fp represents prime field elements as positive integers less than FpOrder
type Fp struct{ i fpMont }

func (z Fp) String() string            { x := z.fromMont(); return conv.Uint64Le2Hex(x[:]) }
func (z Fp) Bytes() []byte             { x := z.fromMont(); return conv.Uint64Le2BytesLe(x[:]) }
func (z *Fp) Set(x *Fp)                { z.i = x.i }
func (z *Fp) SetUint64(n uint64)       { z.toMont(&fpRaw{n}) }
func (z *Fp) SetInt64(n int64)         { z.SetUint64(uint64(-n)); z.Neg() }
func (z *Fp) SetOne()                  { z.SetUint64(1) }
func (z *Fp) Random(r io.Reader) error { return randomInt(z.i[:], r, fpOrder[:]) }
func (z Fp) IsZero() bool              { return z.IsEqual(&Fp{}) }
func (z Fp) IsEqual(x *Fp) bool        { return ctUint64Eq(z.i[:], x.i[:]) == 1 }
func (z *Fp) Neg()                     { fiatFpMontSub(&z.i, &fpMont{}, &z.i) }
func (z *Fp) Add(x, y *Fp)             { fiatFpMontAdd(&z.i, &x.i, &y.i) }
func (z *Fp) Sub(x, y *Fp)             { fiatFpMontSub(&z.i, &x.i, &y.i) }
func (z *Fp) Mul(x, y *Fp)             { fiatFpMontMul(&z.i, &x.i, &y.i) }
func (z *Fp) Sqr(x *Fp)                { fiatFpMontSquare(&z.i, &x.i) }
func (z *Fp) Inv(x *Fp)                { z.exp(x, fpOrderMinus2[:]) }
func (z *Fp) toMont(in *fpRaw)         { fiatFpMontMul(&z.i, in, &fpRSquare) }
func (z Fp) fromMont() (out fpRaw)     { fiatFpMontMul(&out, &z.i, &fpMont{1}); return }

// FpOrder is the order of the base field for towering.
//  FpOrder = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab.
func FpOrder() []byte { o := fpOrder; return o[:] }

// exp calculates z=x^n, where n is in little-endian order.
func (z *Fp) exp(x *Fp, n []byte) {
	zz := new(Fp)
	zz.SetOne()
	for i := 8*len(n) - 1; i >= 0; i-- {
		zz.Sqr(zz)
		bit := 0x1 & (n[i/8] >> uint(i%8))
		if bit != 0 {
			zz.Mul(zz, x)
		}
	}
	z.Set(zz)
}

func (z *Fp) Sqrt(x *Fp) (isQR bool) {
	var t, t2 Fp
	t.exp(x, fpOrderPlus1Div4[:])
	t2.Sqr(&t)
	if t2.IsEqual(x) {
		z.Set(&t)
		return true
	}
	return false
}

// SetBytes reconstructs a Fp from a slice that must have at least
// FpSize bytes and contain a number (in little-endian order) from 0
// to FpOrder-1.
func (z *Fp) SetBytes(data []byte) error {
	in64 := &fpRaw{}
	err := setBytes(in64[:], data[:FpSize], fpOrder[:])
	if err == nil {
		z.toMont(in64)
	}
	return err
}

// SetString reconstructs a Fp from a numeric string from 0 to FpOrder-1.
func (z *Fp) SetString(s string) error {
	in64 := &fpRaw{}
	err := setString(in64[:], s, fpOrder[:])
	if err == nil {
		z.toMont(in64)
	}
	return err
}

var (
	// fpOrder is the order of the Fp field.
	fpOrder = [FpSize]byte{
		0xab, 0xaa, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xb9,
		0xff, 0xff, 0x53, 0xb1, 0xfe, 0xff, 0xab, 0x1e,
		0x24, 0xf6, 0xb0, 0xf6, 0xa0, 0xd2, 0x30, 0x67,
		0xbf, 0x12, 0x85, 0xf3, 0x84, 0x4b, 0x77, 0x64,
		0xd7, 0xac, 0x4b, 0x43, 0xb6, 0xa7, 0x1b, 0x4b,
		0x9a, 0xe6, 0x7f, 0x39, 0xea, 0x11, 0x01, 0x1a,
	}
	// fpOrderMinus2 is the fpOrder minus two used for inversion.
	fpOrderMinus2 = [FpSize]byte{
		0xa9, 0xaa, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xb9,
		0xff, 0xff, 0x53, 0xb1, 0xfe, 0xff, 0xab, 0x1e,
		0x24, 0xf6, 0xb0, 0xf6, 0xa0, 0xd2, 0x30, 0x67,
		0xbf, 0x12, 0x85, 0xf3, 0x84, 0x4b, 0x77, 0x64,
		0xd7, 0xac, 0x4b, 0x43, 0xb6, 0xa7, 0x1b, 0x4b,
		0x9a, 0xe6, 0x7f, 0x39, 0xea, 0x11, 0x01, 0x1a,
	}
	// fpRSquare is R^2 mod fpOrder, where R=2^384.
	fpRSquare = fpMont{
		0xf4df1f341c341746, 0x0a76e6a609d104f1,
		0x8de5476c4c95b6d5, 0x67eb88a9939d83c0,
		0x9a793e85b519952d, 0x11988fe592cae3aa,
	}
	// fpOrderPlus1Div4 is (fpOrder + 1)/4 used for square-root.
	fpOrderPlus1Div4 = [FpSize]byte{
		0xab, 0xea, 0xff, 0xff, 0xff, 0xbf, 0x7f, 0xee,
		0xff, 0xff, 0x54, 0xac, 0xff, 0xff, 0xaa, 0x07,
		0x89, 0x3d, 0xac, 0x3d, 0xa8, 0x34, 0xcc, 0xd9,
		0xaf, 0x44, 0xe1, 0x3c, 0xe1, 0xd2, 0x1d, 0xd9,
		0x35, 0xeb, 0xd2, 0x90, 0xed, 0xe9, 0xc6, 0x92,
		0xa6, 0xf9, 0x5f, 0x8e, 0x7a, 0x44, 0x80, 0x06,
	}
)
