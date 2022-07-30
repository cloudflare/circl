// Package goldilocks provides arithmetic operations on the Goldilocks (edwards448) curve.
//
// Goldilocks Curve
//
// The goldilocks curve is defined over GF(2^448-2^224-1) as
//  Goldilocks: ax^2+y^2 = 1 + dx^2y^2, where a=1 and d=-39081.
// This curve was proposed by Hamburg (1) and is also known as edwards448
// after RFC-7748 (2).
//
// The datatypes Point and Scalar provide methods to perform arithmetic
// operations on the Goldilocks curve.
//
// References
//
// (1) https://www.shiftleft.org/papers/goldilocks
//
// (2) https://tools.ietf.org/html/rfc7748
package goldilocks

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"

	ted "github.com/cloudflare/circl/ecc/goldilocks/internal/ted448"
	fp "github.com/cloudflare/circl/math/fp448"
)

// Point defines a point on the Goldilocks curve using extended projective
// coordinates. For any affine point (x,y) it holds x = X/Z, y = Y/Z, and
// T = Ta*Tb = X*Y/Z.
type Point ted.Point

// Identity returns the identity point.
func Identity() Point { return Point(ted.Identity()) }

// Generator returns the generator point.
func Generator() Point { return Point{X: genX, Y: genY, Z: fp.One(), Ta: genX, Tb: genY} }

// Order returns the number of points in the prime subgroup in little-endian order.
func Order() []byte { r := ted.Order(); return r[:] }

// ParamD is the D parameter of the Goldilocks curve, D=-39081 in Fp.
func ParamD() fp.Elt { return paramD }

func (P Point) String() string        { return ted.Point(P).String() }
func (P *Point) ToAffine()            { (*ted.Point)(P).ToAffine() }
func (P *Point) Neg()                 { (*ted.Point)(P).Neg() }
func (P *Point) IsEqual(Q *Point) int { return (*ted.Point)(P).IsEqual((*ted.Point)(Q)) }
func (P *Point) Double()              { P.Add(P) }
func (P *Point) Add(Q *Point) {
	// Formula as in Eq.(5) of "Twisted Edwards Curves Revisited" by
	// Hisil H., Wong K.KH., Carter G., Dawson E. (2008)
	// https://doi.org/10.1007/978-3-540-89255-7_20
	// Formula for curves with a=1.
	Px, Py, Pz, Pta, Ptb := &P.X, &P.Y, &P.Z, &P.Ta, &P.Tb
	Qx, Qy, Qz, Qta, Qtb := &Q.X, &Q.Y, &Q.Z, &Q.Ta, &Q.Tb

	a, b, c, d := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	e, f, g, h := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	ee, ff := &fp.Elt{}, &fp.Elt{}

	fp.Mul(a, Px, Qx)     // A = x1*x2
	fp.Mul(b, Py, Qy)     // B = y1*y2
	fp.Mul(c, Pta, Ptb)   // C = d*t1*t2
	fp.Mul(c, c, Qta)     //
	fp.Mul(c, c, Qtb)     //
	fp.Mul(c, c, &paramD) //
	fp.Mul(d, Pz, Qz)     // D = z1*z2
	fp.Add(ee, Px, Py)    // x1+y1
	fp.Add(ff, Qx, Qy)    // x2+y2
	fp.Mul(e, ee, ff)     // E = (x1+y1)*(x2+y2)-A-B
	fp.Sub(e, e, a)       //
	fp.Sub(e, e, b)       //
	fp.Sub(f, d, c)       // F = D-C
	fp.Add(g, d, c)       // g = D+C
	fp.Sub(h, b, a)       // H = B-A
	fp.Mul(Px, e, f)      // X = E * F
	fp.Mul(Py, g, h)      // Y = G * H
	fp.Mul(Pz, f, g)      // Z = F * G
	P.Ta, P.Tb = *e, *h   // T = E * H
}

func (P *Point) CMov(Q *Point, b uint) {
	fp.Cmov(&P.X, &Q.X, b)
	fp.Cmov(&P.Y, &Q.Y, b)
	fp.Cmov(&P.Z, &Q.Z, b)
	fp.Cmov(&P.Ta, &Q.Ta, b)
	fp.Cmov(&P.Tb, &Q.Tb, b)
}

// ScalarBaseMult calculates P = kG, where G is the generator of the Goldilocks
// curve. This function runs in constant time.
func (P *Point) ScalarBaseMult(k *Scalar) {
	// TODO: recheck if this works for any scalar, likely yes.
	k4 := &ted.Scalar{}
	divBy4ModOrder(k4, &k.k)
	var Q ted.Point
	ted.ScalarBaseMult(&Q, k4)
	push(P, &Q)
}

// CombinedMult calculates P = mG+nQ, where G is the generator of the Goldilocks
// curve. This function does NOT run in constant time as is only used for
// signature verification.
func (P *Point) CombinedMult(m, n *Scalar, Q *Point) {
	var m4, n4 ted.Scalar
	divBy4ModOrder(&m4, &m.k)
	divBy4ModOrder(&n4, &n.k)
	var R, phiQ ted.Point
	pull(&phiQ, Q)
	ted.CombinedMult(&R, &m4, &n4, &phiQ)
	push(P, &R)
}

func (P *Point) ScalarMult(k *Scalar, Q *Point) {
	var T [4]Point
	T[0] = Identity()
	T[1] = *Q
	T[2] = *Q
	T[2].Double()
	T[3] = T[2]
	T[3].Add(Q)

	var R Point
	kMod4 := int32(k.k[0] & 0b11)
	for i := range T {
		R.CMov(&T[i], uint(subtle.ConstantTimeEq(int32(i), kMod4)))
	}

	var kDiv4 ted.Scalar
	for i := 0; i < ScalarSize-1; i++ {
		kDiv4[i] = (k.k[i+1] << 6) | (k.k[i] >> 2)
	}
	kDiv4[ScalarSize-1] = k.k[ScalarSize-1] >> 2

	var phikQ, phiQ ted.Point
	pull(&phiQ, Q)
	ted.ScalarMult(&phikQ, &kDiv4, &phiQ)
	push(P, &phikQ)
	P.Add(&R)
}

// divBy4ModOrder calculates z = x/4 mod order.
func divBy4ModOrder(z, x *ted.Scalar) {
	z.Mul(x, &invFour)
}

// pull calculates Q = Iso4(P), where P is a Goldilocks point and Q is a ted448 point.
func pull(Q *ted.Point, P *Point) { isogeny4(Q, (*ted.Point)(P), true) }

// push calculates Q = Iso4^-1(P), where P is a ted448 point and Q is a Goldilocks point.
func push(Q *Point, P *ted.Point) { isogeny4((*ted.Point)(Q), P, false) }

// isogeny4 is a birational map between ted448 and Goldilocks curves.
func isogeny4(Q, P *ted.Point, isPull bool) {
	Px, Py, Pz := &P.X, &P.Y, &P.Z
	a, b, c, d, e, f, g, h := &Q.X, &Q.Y, &Q.Z, &fp.Elt{}, &Q.Ta, &Q.X, &Q.Y, &Q.Tb
	fp.Add(e, Px, Py) // x+y
	fp.Sqr(a, Px)     // A = x^2
	fp.Sqr(b, Py)     // B = y^2
	fp.Sqr(c, Pz)     // z^2
	fp.Add(c, c, c)   // C = 2*z^2
	if isPull {
		*d = *a // D = A
	} else {
		fp.Neg(d, a) // D = -A
	}
	fp.Sqr(e, e)       // (x+y)^2
	fp.Sub(e, e, a)    // (x+y)^2-A
	fp.Sub(e, e, b)    // E = (x+y)^2-A-B
	fp.Add(h, b, d)    // H = B+D
	fp.Sub(g, b, d)    // G = B-D
	fp.Sub(f, c, h)    // F = C-H
	fp.Mul(&Q.Z, f, g) // Z = F * G
	fp.Mul(&Q.X, e, f) // X = E * F
	fp.Mul(&Q.Y, g, h) // Y = G * H, // T = E * H
}

type Scalar struct{ k ted.Scalar }

func (z Scalar) String() string         { return z.k.String() }
func (z *Scalar) Add(x, y *Scalar)      { z.k.Add(&x.k, &y.k) }
func (z *Scalar) Sub(x, y *Scalar)      { z.k.Sub(&x.k, &y.k) }
func (z *Scalar) Mul(x, y *Scalar)      { z.k.Mul(&x.k, &y.k) }
func (z *Scalar) Neg(x *Scalar)         { z.k.Neg(&x.k) }
func (z *Scalar) Inv(x *Scalar)         { z.k.Inv(&x.k) }
func (z *Scalar) IsEqual(x *Scalar) int { return subtle.ConstantTimeCompare(z.k[:], x.k[:]) }
func (z *Scalar) SetUint64(n uint64)    { z.k = ted.Scalar{}; binary.LittleEndian.PutUint64(z.k[:], n) }

// UnmarshalBinary recovers the scalar from its byte representation in big-endian order.
func (z *Scalar) UnmarshalBinary(b []byte) error { return z.k.UnmarshalBinary(b) }

// MarshalBinary returns the scalar byte representation in big-endian order.
func (z *Scalar) MarshalBinary() ([]byte, error) { return z.k.MarshalBinary() }

// ToBytesLE returns the scalar byte representation in little-endian order.
func (z *Scalar) ToBytesLE() []byte { return z.k.ToBytesLE() }

// ToBytesBE returns the scalar byte representation in big-endian order.
func (z *Scalar) ToBytesBE() []byte { return z.k.ToBytesBE() }

// FromBytesLE stores z = x mod order, where x is a number stored in little-endian order.
func (z *Scalar) FromBytesLE(x []byte) { z.k.FromBytesLE(x) }

// FromBytesBE stores z = x mod order, where x is a number stored in big-endian order.
func (z *Scalar) FromBytesBE(x []byte) { z.k.FromBytesBE(x) }

var (
	// genX is the x-coordinate of the generator of Goldilocks curve.
	genX = fp.Elt{ // little-endian
		0x5e, 0xc0, 0x0c, 0xc7, 0x2b, 0xa8, 0x26, 0x26,
		0x8e, 0x93, 0x00, 0x8b, 0xe1, 0x80, 0x3b, 0x43,
		0x11, 0x65, 0xb6, 0x2a, 0xf7, 0x1a, 0xae, 0x12,
		0x64, 0xa4, 0xd3, 0xa3, 0x24, 0xe3, 0x6d, 0xea,
		0x67, 0x17, 0x0f, 0x47, 0x70, 0x65, 0x14, 0x9e,
		0xda, 0x36, 0xbf, 0x22, 0xa6, 0x15, 0x1d, 0x22,
		0xed, 0x0d, 0xed, 0x6b, 0xc6, 0x70, 0x19, 0x4f,
	}
	// genY is the y-coordinate of the generator of Goldilocks curve.
	genY = fp.Elt{ // little-endian
		0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98,
		0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd, 0xfd,
		0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a,
		0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87,
		0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b,
		0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
		0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69,
	}
	// paramD is the D parameter of the Goldilocks curve, D=-39081 in Fp.
	paramD = fp.Elt{ // little-endian
		0x56, 0x67, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
	// invFour is 1/4 mod order, where order = ted.Order().
	invFour = ted.Scalar{ // little-endian
		0x3d, 0x11, 0xd6, 0xaa, 0xa4, 0x30, 0xde, 0x48,
		0xd5, 0x63, 0x71, 0xa3, 0x9c, 0x30, 0x5b, 0x08,
		0xa4, 0x8d, 0xb5, 0x6b, 0xd2, 0xb6, 0x13, 0x71,
		0xfa, 0x88, 0x32, 0xdf, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
	}
)

// isLessThan returns 1 if 0 <= x < y, and assumes that slices are of the
// same length and are interpreted in little-endian order.
func isLessThan(x, y []byte) int {
	i := len(x) - 1
	for i > 0 && x[i] == y[i] {
		i--
	}
	xi := int(x[i])
	yi := int(y[i])
	return ((xi - yi) >> (bits.UintSize - 1)) & 1
}

// Decode if succeeds constructs a point by decoding the first
// EncodingSize bytes of data.
func (P *Point) Decode(data *[EncodingSize]byte) error {
	x, y := &fp.Elt{}, &fp.Elt{}
	isByteZero := subtle.ConstantTimeByteEq(data[EncodingSize-1]&0x7F, 0x00)
	signX := int(data[EncodingSize-1] >> 7)
	copy(y[:], data[:fp.Size])
	p := fp.P()
	isLessThanP := isLessThan(y[:], p[:])

	u, v := &fp.Elt{}, &fp.Elt{}
	one := fp.One()
	fp.Sqr(u, y)                // u = y^2
	fp.Mul(v, u, &paramD)       // v = dy^2
	fp.Sub(u, u, &one)          // u = y^2-1
	fp.Sub(v, v, &one)          // v = dy^2-a
	isQR := fp.InvSqrt(x, u, v) // x = sqrt(u/v)
	isValidXSign := 1 - (fp.IsZero(x) & signX)
	fp.Neg(u, x)                            // u = -x
	fp.Cmov(x, u, uint(signX^fp.Parity(x))) // if signX != x mod 2

	b0 := isByteZero
	b1 := isLessThanP
	b2 := isQR
	b3 := isValidXSign
	b := uint(subtle.ConstantTimeEq(int32(8*b3+4*b2+2*b1+b0), 0xF))
	fp.Cmov(&P.X, x, b)
	fp.Cmov(&P.Y, y, b)
	fp.Cmov(&P.Ta, x, b)
	fp.Cmov(&P.Tb, y, b)
	fp.Cmov(&P.Z, &one, b)
	if b == 0 {
		return ErrInvalidDecoding
	}
	return nil
}

// Encode sets data with the unique encoding of the point P.
func (P *Point) Encode(data *[EncodingSize]byte) error {
	P.ToAffine()
	data[EncodingSize-1] = (P.X[0] & 1) << 7
	return fp.ToBytes(data[:fp.Size], &P.Y)
}

const (
	// EncodingSize is the size (in bytes) of an encoded point on the Goldilocks curve.
	EncodingSize = fp.Size + 1
	// ScalarSize is the size (in bytes) of scalars.
	ScalarSize = ted.ScalarSize
)

// ErrInvalidDecoding alerts of an error during decoding a point.
var ErrInvalidDecoding = errors.New("goldilocks: invalid point decoding")
