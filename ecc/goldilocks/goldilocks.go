// Package goldilocks provides arithmetic operations on the Goldilocks curve.
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
	"errors"
	"unsafe"

	"github.com/cloudflare/circl/internal/ted448"
	fp "github.com/cloudflare/circl/math/fp448"
)

type Scalar = ted448.Scalar

type Point ted448.Point

// EncodingSize is the size (in bytes) of an encoded point on the Goldilocks curve.
const EncodingSize = fp.Size + 1

// ErrInvalidDecoding alerts of an error during decoding a point.
var ErrInvalidDecoding = errors.New("invalid decoding")

// Decode if succeeds constructs a point by decoding the first
// EncodingSize bytes of data.
func (P *Point) Decode(data *[EncodingSize]byte) error {
	x, y := &fp.Elt{}, &fp.Elt{}
	isByteZero := (data[EncodingSize-1] & 0x7F) == 0x00
	signX := data[EncodingSize-1] >> 7
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
	isValidXSign := !(fp.IsZero(x) && signX == 1)
	fp.Neg(u, x)                        // u = -x
	fp.Cmov(x, u, uint(signX^(x[0]&1))) // if signX != x mod 2

	isValid := isByteZero && isLessThanP && isQR && isValidXSign
	b := uint(*(*byte)(unsafe.Pointer(&isValid)))
	fp.Cmov(&P.X, x, b)
	fp.Cmov(&P.Y, y, b)
	fp.Cmov(&P.Ta, x, b)
	fp.Cmov(&P.Tb, y, b)
	fp.Cmov(&P.Z, &one, b)
	if !isValid {
		return ErrInvalidDecoding
	}
	return nil
}

// Encode sets data with the unique encoding of the point P.
func (P *Point) Encode(data *[EncodingSize]byte) error {
	x, y, invZ := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	fp.Inv(invZ, &P.Z)    // 1/z
	fp.Mul(x, &P.X, invZ) // x/z
	fp.Mul(y, &P.Y, invZ) // y/z
	fp.Modp(x)
	fp.Modp(y)
	data[EncodingSize-1] = (x[0] & 1) << 7
	return fp.ToBytes(data[:fp.Size], y)
}

// ScalarBaseMult calculates P = kG, where G is the generator of the Goldilocks
// curve. This function runs in constant time.
func (P *Point) ScalarBaseMult(k *Scalar) {
	k4 := &Scalar{}
	divBy4(k4, k)
	var Q ted448.Point
	ted448.ScalarBaseMult(&Q, k4)
	push(P, &Q)
}

// CombinedMult calculates P = mG+nQ, where G is the generator of the Goldilocks
// curve. This function does NOT run in constant time as is only used for
// signature verification.
func (P *Point) CombinedMult(m, n *Scalar, Q *Point) {
	m4, n4 := &Scalar{}, &Scalar{}
	divBy4(m4, m)
	divBy4(n4, n)
	var R, phiQ ted448.Point
	pull(&phiQ, Q)
	ted448.CombinedMult(&R, m4, n4, &phiQ)
	push(P, &R)
}

func (P *Point) Neg() { fp.Neg(&P.X, &P.X); fp.Neg(&P.Ta, &P.Ta) }

// Order returns a scalar with the order of the group.
func Order() Scalar { return ted448.Order() }

// divBy4 calculates z = x/4 mod order.
func divBy4(z, x *Scalar) { z.Mul(x, &invFour) }

// pull calculates Q = Iso4(P), where P is a Goldilocks point and Q is a ted448 point.
func pull(Q *ted448.Point, P *Point) { isogeny4(Q, (*ted448.Point)(P), true) }

// push calculates Q = Iso4^-1(P), where P is a ted448 point and Q is a Goldilocks point.
func push(Q *Point, P *ted448.Point) { isogeny4((*ted448.Point)(Q), P, false) }

// isogeny4 is a birational map between ted448 and Goldilocks curves.
func isogeny4(Q, P *ted448.Point, isPull bool) {
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

// isLessThan returns true if 0 <= x < y, and assumes that slices are of the
// same length and are interpreted in little-endian order.
func isLessThan(x, y []byte) bool {
	i := len(x) - 1
	for i > 0 && x[i] == y[i] {
		i--
	}
	return x[i] < y[i]
}

var (
	// invFour is 1/4 mod order, where order = ted448.Order().
	invFour = Scalar{
		0x3d, 0x11, 0xd6, 0xaa, 0xa4, 0x30, 0xde, 0x48,
		0xd5, 0x63, 0x71, 0xa3, 0x9c, 0x30, 0x5b, 0x08,
		0xa4, 0x8d, 0xb5, 0x6b, 0xd2, 0xb6, 0x13, 0x71,
		0xfa, 0x88, 0x32, 0xdf, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
	}
	// paramD is the D parameter of the Goldilocks curve, D=-39081 in Fp.
	paramD = fp.Elt{
		0x56, 0x67, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
)
