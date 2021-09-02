package ff

import (
	"errors"
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
func (z Fp) Bytes() []byte             { x := z.fromMont(); return conv.Uint64Le2BytesBe(x[:]) }
func (z *Fp) Set(x *Fp)                { z.i = x.i }
func (z *Fp) SetUint64(n uint64)       { z.toMont(&fpRaw{n}) }
func (z *Fp) SetOne()                  { z.SetUint64(1) }
func (z *Fp) Random(r io.Reader) error { return randomInt(z.i[:], r, fpOrder[:]) }

// IsZero returns 1 if z == 0 and 0 otherwise.
func (z Fp) IsZero() int { return z.IsEqual(&Fp{}) }

// IsEqual returns 1 if z == x and 0 otherwise.
func (z Fp) IsEqual(x *Fp) int     { return ctUint64Eq(z.i[:], x.i[:]) }
func (z *Fp) Neg()                 { fiatFpMontSub(&z.i, &fpMont{}, &z.i) }
func (z *Fp) Add(x, y *Fp)         { fiatFpMontAdd(&z.i, &x.i, &y.i) }
func (z *Fp) Sub(x, y *Fp)         { fiatFpMontSub(&z.i, &x.i, &y.i) }
func (z *Fp) Mul(x, y *Fp)         { fiatFpMontMul(&z.i, &x.i, &y.i) }
func (z *Fp) Sqr(x *Fp)            { fiatFpMontSquare(&z.i, &x.i) }
func (z *Fp) Inv(x *Fp)            { z.ExpVarTime(x, fpOrderMinus2[:]) }
func (z *Fp) toMont(in *fpRaw)     { fiatFpMontMul(&z.i, in, &fpRSquare) }
func (z Fp) fromMont() (out fpRaw) { fiatFpMontMul(&out, &z.i, &fpMont{1}); return }
func (z Fp) Sgn0() int             { zz := z.fromMont(); return int(zz[0] & 1) }

// CMov sets z=x if b == 0 and z=y if b == 1. Its behavior is undefined if b takes any other value.
func (z *Fp) CMov(x, y *Fp, b int) {
	mask := 0 - uint64(b&0x1)
	for i := range z.i {
		z.i[i] = (x.i[i] &^ mask) | (y.i[i] & mask)
	}
}

// FpOrder is the order of the base field for towering returned as a big-endian slice.
//  FpOrder = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab.
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
	z.Set(zz)
}

// SetBytes reconstructs a Fp from a slice that must have at least
// FpSize bytes and contain a number (in big-endian order) from 0
// to FpOrder-1.
func (z *Fp) SetBytes(data []byte) error {
	if len(data) < FpSize {
		return errors.New("input length incorrect")
	}
	in64, err := setBytes(data[:FpSize], fpOrder[:])
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
	// fpOrderMinus2 is the fpOrder minus two used for inversion (big-endian).
	fpOrderMinus2 = [FpSize]byte{
		0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a,
		0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b, 0xac, 0xd7,
		0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf,
		0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0, 0xf6, 0x24,
		0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff,
		0xb9, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xa9,
	}
	// fpRSquare is R^2 mod fpOrder, where R=2^384 (little-endian).
	fpRSquare = fpMont{
		0xf4df1f341c341746, 0x0a76e6a609d104f1,
		0x8de5476c4c95b6d5, 0x67eb88a9939d83c0,
		0x9a793e85b519952d, 0x11988fe592cae3aa,
	}
)
