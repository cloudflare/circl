// Package decaf provides a prime-order group derived from a quotient of
// Edwards curves.
//
// Decaf Group
//
// Decaf (3) is a prime-order group constructed as a quotient of groups. A Decaf
// element can be represented by any point in the coset P+J[2], where J is a
// Jacobi quartic curve and J[2] are its 2-torsion points.
// Since P+J[2] has four points, Decaf specifies rules to choose one canonical
// representative, which has a unique encoding. Two representations are
// equivalent if they belong to the same coset.
//
// The types Elt and Scalar provide methods to perform arithmetic operations on
// the Decaf group.
//
// Version
//
// This implementation uses Decaf v1.0 of the encoding (see (4,5) for a complete
// specification).
//
// References
//
// (1) https://www.shiftleft.org/papers/goldilocks
//
// (2) https://tools.ietf.org/html/rfc7748
//
// (3) https://doi.org/10.1007/978-3-662-47989-6_34 and https://www.shiftleft.org/papers/decaf
//
// (4) https://sourceforge.net/p/ed448goldilocks/code/ci/v1.0/tree/
//
// (5) https://mailarchive.ietf.org/arch/msg/cfrg/S4YUTt_5eD4kwYbDuhEK0tXT1aM/
package decaf

import (
	"unsafe"

	"github.com/cloudflare/circl/internal/ted448"
	fp "github.com/cloudflare/circl/math/fp448"
)

//  Decaf v1.0 of the encoding.
const Version = "v1.0"

// Elt is an element of the Decaf group. It must be always initialized using
// one of the Decaf functions.
type Elt struct{ p ted448.Point }

// Scalar represents a positive integer stored in little-endian order.
type Scalar = ted448.Scalar

func (e Elt) String() string { return e.p.String() }

// IsValid returns True if a is a valid element of the group.
func IsValid(a *Elt) bool { return ted448.IsOnCurve(&a.p) }

// Identity returns the identity element of the group.
func Identity() *Elt { return &Elt{ted448.Identity()} }

// Generator returns the generator element of the group.
func Generator() *Elt { return &Elt{ted448.Generator()} }

// Order returns a scalar with the order of the group.
func Order() Scalar { return ted448.Order() }

// Neg calculates c=-a, where - is the inverse of the group operation.
func Neg(c, a *Elt) { c.p = a.p; c.p.Neg() }

// Add calculates c=a+b, where + is the group operation.
func Add(c, a, b *Elt) { q := a.p; q.Add(&b.p); c.p = q }

// Double calculates c=a+a, where + is the group operation.
func Double(c, a *Elt) { c.p = a.p; c.p.Double() }

// Mul calculates c=n*a, where * is scalar multiplication on the group.
func Mul(c *Elt, n *Scalar, a *Elt) { ted448.ScalarMult(&c.p, n, &a.p) }

// MulGen calculates c=n*g, where * is scalar multiplication on the group,
// and g is the generator of the group.
func MulGen(c *Elt, n *Scalar) { ted448.ScalarBaseMult(&c.p, n) }

// IsIdentity returns True if e is the identity of the group.
func (e *Elt) IsIdentity() bool { return fp.IsZero(&e.p.X) && !fp.IsZero(&e.p.Y) && !fp.IsZero(&e.p.Z) }

// IsEqual returns True if e=a, where = is an equivalence relation.
func (e *Elt) IsEqual(a *Elt) bool {
	l, r := &fp.Elt{}, &fp.Elt{}
	fp.Mul(l, &e.p.X, &a.p.Y)
	fp.Mul(r, &a.p.X, &e.p.Y)
	fp.Sub(l, l, r)
	return fp.IsZero(l)
}

// UnmarshalBinary interprets the first EncodingSize bytes passed in data, and
// returns a Decaf element.
func (e *Elt) UnmarshalBinary(data []byte) error {
	if len(data) < EncodingSize {
		return ErrInvalidDecoding
	}

	s := &fp.Elt{}
	copy(s[:], data[:EncodingSize])
	p := fp.P()
	isLessThanP := isLessThan(s[:], p[:])
	isPositiveS := fp.Parity(s) == 0

	den, num := &fp.Elt{}, &fp.Elt{}
	isr, altx, t0 := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	x, y := &fp.Elt{}, &fp.Elt{}
	one := fp.One()
	paramD := ted448.ParamD()
	fp.Sqr(t0, s)                     // t0  = s^2
	fp.Sub(den, &one, t0)             // den = 1 + a*s^2
	fp.Add(y, &one, t0)               // y   = 1 - a*s^2
	fp.Mul(num, t0, &paramD)          // num = d*s^2
	fp.Add(num, num, num)             //     = 2*d*s^2
	fp.Add(num, num, num)             //     = 4*d*s^2
	fp.Sqr(t0, den)                   // t0  = den^2 = (1 + a*s^2)^2
	fp.Sub(num, t0, num)              // num = den^2 - 4*d*s^2
	fp.Mul(t0, t0, num)               // t0  = den^2*num
	isQR := fp.InvSqrt(isr, &one, t0) // isr = 1/(den*sqrt(num))
	fp.Mul(altx, isr, den)            // altx = isr*den
	fp.Mul(altx, altx, s)             //      = s*isr*den
	fp.Add(altx, altx, altx)          //      = 2*s*isr*den
	fp.Mul(altx, altx, &sqrtAMinusD)  //      = 2*s*isr*den*sqrt(A-D)
	isNegX := fp.Parity(altx)         // isNeg = sgn(altx)
	fp.Neg(t0, isr)                   // t0 = -isr
	fp.Cmov(isr, t0, uint(isNegX))    // if altx is negative then isr = -isr
	fp.Mul(t0, isr, den)              // t0 = isr*den
	fp.Mul(x, t0, isr)                // x = isr^2*den
	fp.Mul(x, x, num)                 // x = isr^2*den*num
	fp.Mul(x, x, s)                   // x = s*isr^2*den*num
	fp.Add(x, x, x)                   // x = 2*s*isr^2*den*num
	fp.Mul(y, y, t0)                  // y = (1 - a*s^2)*isr*den

	isValid := isPositiveS && isLessThanP && isQR
	b := uint(*((*byte)(unsafe.Pointer(&isValid))))
	fp.Cmov(&e.p.X, x, b)
	fp.Cmov(&e.p.Y, y, b)
	fp.Cmov(&e.p.Ta, x, b)
	fp.Cmov(&e.p.Tb, y, b)
	fp.Cmov(&e.p.Z, &one, b)
	if !isValid {
		return ErrInvalidDecoding
	}
	return nil
}

// MarshalBinary returns a unique encoding of the element e.
func (e *Elt) MarshalBinary() ([]byte, error) {
	var encS [EncodingSize]byte
	err := e.marshalBinary(encS[:])
	return encS[:], err
}

func (e *Elt) marshalBinary(enc []byte) error {
	x, ta, tb, z := &e.p.X, &e.p.Ta, &e.p.Tb, &e.p.Z
	t, t2, s := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	one := fp.One()
	fp.Mul(t, ta, tb)             // t = ta*tb
	t0, t1 := *x, *t              // (t0,t1) = (x,t)
	fp.AddSub(&t0, &t1)           // (t0,t1) = (x+t,x-t)
	fp.Mul(&t1, &t0, &t1)         // t1 = num = (x+t)*(x-t) = x^2*(z^2-y^2)/z^2
	fp.Mul(&t0, &t1, &aMinusD)    // t0 = (a-d)*(x+t)*(x-t) = (a-d)*x^2*(z^2-y^2)/z^2
	fp.Sqr(t2, x)                 // t2 = x^2
	fp.Mul(&t0, &t0, t2)          // t0 = x^2*(a-d)*(x+t)*(x-t) = (a-d)*x^4*(z^2-y^2)/z^2
	fp.InvSqrt(&t0, &one, &t0)    // t0 = isr = z/(x^2*sqrt((a-d)*(z^2-y^2)))
	fp.Mul(&t1, &t1, &t0)         // t1 = ratio = (z^2-y^2)/(z*sqrt((a-d)*(z^2-y^2)))
	fp.Mul(t2, &t1, &sqrtAMinusD) // t2 = altx = sqrt((z^2-y^2))/z
	isNeg := fp.Parity(t2)        // isNeg = sgn(t2)
	fp.Neg(t2, &t1)               // t2 = -t1
	fp.Cmov(&t1, t2, uint(isNeg)) // if t2 is negative then t1 = -t1
	fp.Mul(s, &t1, z)             // s = t1*z
	fp.Sub(s, s, t)               // s = t1*z - t
	fp.Mul(s, s, x)               // s = x*(t1*z - t)
	fp.Mul(s, s, &t0)             // s = isr*x*(t1*z - t)
	fp.Mul(s, s, &aMinusD)        // s = (a-d)*isr*x*(t1*z - t)
	isNeg = fp.Parity(s)          // isNeg = sgn(s)
	fp.Neg(&t0, s)                // t0 = -s
	fp.Cmov(s, &t0, uint(isNeg))  // if s is negative then s = -s
	return fp.ToBytes(enc[:], s)
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
