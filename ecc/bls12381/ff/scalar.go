package ff

import (
	"io"

	"github.com/cloudflare/circl/internal/conv"
)

// ScalarSize is the length in bytes of a Scalar.
const ScalarSize = 32

// scMont represents an element in Montgomery domain.
type scMont = [ScalarSize / 8]uint64

// scRaw represents a scalar in binary format.
type scRaw = [ScalarSize / 8]uint64

// Scalar represents positive integers less than ScalarOrder
type Scalar struct{ i scMont }

func (z Scalar) String() string            { x := z.fromMont(); return conv.Uint64Le2Hex(x[:]) }
func (z Scalar) Bytes() []byte             { x := z.fromMont(); return conv.Uint64Le2BytesLe(x[:]) }
func (z *Scalar) Set(x *Scalar)            { z.i = x.i }
func (z *Scalar) SetUint64(n uint64)       { z.toMont(&scRaw{n}) }
func (z *Scalar) SetInt64(n int64)         { z.SetUint64(uint64(-n)); z.Neg() }
func (z *Scalar) SetOne()                  { z.SetUint64(1) }
func (z *Scalar) Random(r io.Reader) error { return randomInt(z.i[:], r, scOrder[:]) }
func (z Scalar) IsZero() bool              { return z.IsEqual(&Scalar{}) }
func (z Scalar) IsEqual(x *Scalar) bool    { return ctUint64Eq(z.i[:], x.i[:]) == 1 }
func (z *Scalar) Neg()                     { fiatScMontSub(&z.i, &scMont{}, &z.i) }
func (z *Scalar) Add(x, y *Scalar)         { fiatScMontAdd(&z.i, &x.i, &y.i) }
func (z *Scalar) Sub(x, y *Scalar)         { fiatScMontSub(&z.i, &x.i, &y.i) }
func (z *Scalar) Mul(x, y *Scalar)         { fiatScMontMul(&z.i, &x.i, &y.i) }
func (z *Scalar) Sqr(x *Scalar)            { fiatScMontSquare(&z.i, &x.i) }
func (z *Scalar) Inv(x *Scalar)            { z.expVarTime(x, scOrderMinus2[:]) }
func (z *Scalar) toMont(in *scRaw)         { fiatScMontMul(&z.i, in, &scRSquare) }
func (z Scalar) fromMont() (out scRaw)     { fiatScMontMul(&out, &z.i, &scMont{1}); return }

// ScalarOrder is the order of the scalar field of the pairing groups.
//  ScalarOrder = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
func ScalarOrder() []byte { o := scOrder; return o[:] }

// exp calculates z=x^n, where n is in little-endian order.
func (z *Scalar) expVarTime(x *Scalar, n []byte) {
	zz := new(Scalar)
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

// SetBytes reconstructs a Scalar from a slice that must have at least
// ScalarSize bytes and contain a number (in little-endian order) from 0
// to ScalarOrder-1.
func (z *Scalar) SetBytes(data []byte) error {
	in64 := &scRaw{}
	err := setBytes(in64[:], data[:ScalarSize], scOrder[:])
	if err == nil {
		z.toMont(in64)
	}
	return err
}

// SetString reconstructs a Fp from a numeric string from 0 to ScalarOrder-1.
func (z *Scalar) SetString(s string) error {
	in64 := &scRaw{}
	err := setString(in64[:], s, scOrder[:])
	if err == nil {
		z.toMont(in64)
	}
	return err
}

var (
	// scOrder is the order of the Scalar field.
	scOrder = [ScalarSize]byte{
		0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
		0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd, 0x53,
		0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33,
		0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73,
	}
	// scOrderMinus2 is the scOrder minus two used for inversion.
	scOrderMinus2 = [ScalarSize]byte{
		0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
		0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd, 0x53,
		0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33,
		0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73,
	}
	// scRSquare is R^2 mod scOrder, where R=2^256.
	scRSquare = scMont{
		0xc999e990f3f29c6d, 0x2b6cedcb87925c23,
		0x05d314967254398f, 0x0748d9d99f59ff11,
	}
)
