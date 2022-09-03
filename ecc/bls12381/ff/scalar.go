package ff

import (
	"io"

	"github.com/cloudflare/circl/internal/conv"
)

// ScalarSize is the length in bytes of a Scalar.
const ScalarSize = 32

// scMont represents an element in the Montgomery domain (little-endian).
type scMont = [ScalarSize / 8]uint64

// scRaw represents a scalar in the integers domain (little-endian).
type scRaw = [ScalarSize / 8]uint64

// Scalar represents positive integers less than ScalarOrder.
type Scalar struct{ i scMont }

func (z Scalar) String() string            { x := z.fromMont(); return conv.Uint64Le2Hex(x[:]) }
func (z *Scalar) Set(x *Scalar)            { z.i = x.i }
func (z *Scalar) SetUint64(n uint64)       { z.toMont(&scRaw{n}) }
func (z *Scalar) SetOne()                  { z.SetUint64(1) }
func (z *Scalar) Random(r io.Reader) error { return randomInt(z.i[:], r, scOrder[:]) }
func (z Scalar) IsZero() int               { return ctUint64Eq(z.i[:], (&scMont{})[:]) }
func (z Scalar) IsEqual(x *Scalar) int     { return ctUint64Eq(z.i[:], x.i[:]) }
func (z *Scalar) Neg()                     { fiatScMontSub(&z.i, &scMont{}, &z.i) }
func (z *Scalar) Add(x, y *Scalar)         { fiatScMontAdd(&z.i, &x.i, &y.i) }
func (z *Scalar) Sub(x, y *Scalar)         { fiatScMontSub(&z.i, &x.i, &y.i) }
func (z *Scalar) Mul(x, y *Scalar)         { fiatScMontMul(&z.i, &x.i, &y.i) }
func (z *Scalar) Sqr(x *Scalar)            { fiatScMontSquare(&z.i, &x.i) }
func (z *Scalar) Inv(x *Scalar)            { z.expVarTime(x, scOrderMinus2[:]) }
func (z *Scalar) toMont(in *scRaw)         { fiatScMontMul(&z.i, in, &scRSquare) }
func (z Scalar) fromMont() (out scRaw)     { fiatScMontMul(&out, &z.i, &scMont{1}); return }

// ScalarOrder is the order of the scalar field of the pairing groups, order is
// returned as a big-endian slice.
//
//	ScalarOrder = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
func ScalarOrder() []byte { o := scOrder; return o[:] }

// exp calculates z=x^n, where n is in big-endian order.
func (z *Scalar) expVarTime(x *Scalar, n []byte) {
	zz := new(Scalar)
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

// SetBytes assigns to z the number modulo ScalarOrder stored in the slice
// (in big-endian order).
func (z *Scalar) SetBytes(data []byte) {
	in64 := setBytesUnbounded(data, scOrder[:])
	s := &scRaw{}
	copy(s[:], in64[:ScalarSize/8])
	z.toMont(s)
}

// MarshalBinary returns a slice of ScalarSize bytes that contains the minimal
// residue of z such that 0 <= z < ScalarOrder (in big-endian order).
func (z *Scalar) MarshalBinary() ([]byte, error) {
	x := z.fromMont()
	return conv.Uint64Le2BytesBe(x[:]), nil
}

// UnmarshalBinary reconstructs a Scalar from a slice that must have at least
// ScalarSize bytes and contain a number (in big-endian order) from 0
// to ScalarOrder-1.
func (z *Scalar) UnmarshalBinary(data []byte) error {
	if len(data) < ScalarSize {
		return errInputLength
	}
	in64, err := setBytesBounded(data[:ScalarSize], scOrder[:])
	if err == nil {
		s := &scRaw{}
		copy(s[:], in64[:ScalarSize/8])
		z.toMont(s)
	}
	return err
}

// SetString reconstructs a Fp from a numeric string from 0 to ScalarOrder-1.
func (z *Scalar) SetString(s string) error {
	in64, err := setString(s, scOrder[:])
	if err == nil {
		s := &scRaw{}
		copy(s[:], in64[:ScalarSize/8])
		z.toMont(s)
	}
	return err
}

func fiatScMontCmovznzU64(z *uint64, b, x, y uint64) { cselectU64(z, b, x, y) }

var (
	// scOrder is the order of the Scalar field (big-endian).
	scOrder = [ScalarSize]byte{
		0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
		0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
		0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
		0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
	}
	// scOrderMinus2 is the scOrder minus two used for inversion (big-endian).
	scOrderMinus2 = [ScalarSize]byte{
		0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
		0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
		0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
		0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
	}
	// scRSquare is R^2 mod scOrder, where R=2^256 (little-endian).
	scRSquare = scMont{
		0xc999e990f3f29c6d, 0x2b6cedcb87925c23,
		0x05d314967254398f, 0x0748d9d99f59ff11,
	}
)
