package group

import (
	"crypto/subtle"
	"io"
	"math/bits"

	curve "github.com/cloudflare/circl/ecc/goldilocks"
	"github.com/cloudflare/circl/expander"
	fp "github.com/cloudflare/circl/math/fp448"
	"github.com/cloudflare/circl/xof"
)

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
// This implementation is compatible with v03 of draft-irtf-cfrg-ristretto255-decaf448 (4).
//
// References
//
// (1) https://www.shiftleft.org/papers/goldilocks
//
// (2) https://tools.ietf.org/html/rfc7748
//
// (3) https://doi.org/10.1007/978-3-662-47989-6_34 and https://www.shiftleft.org/papers/decaf
//
// (4) https://datatracker.ietf.org/doc/draft-irtf-cfrg-ristretto255-decaf448/

// Decaf448 is a quotient group generated from the edwards448 curve.
var Decaf448 Group = decaf448{}

type decaf448 struct{}

func (g decaf448) String() string      { return "decaf448" }
func (g decaf448) Params() *Params     { return &Params{fp.Size, fp.Size, curve.ScalarSize} }
func (g decaf448) NewElement() Element { return g.Identity() }
func (g decaf448) NewScalar() Scalar   { return new(dScl) }
func (g decaf448) Identity() Element   { return &dElt{curve.Identity()} }
func (g decaf448) Order() Scalar       { r := &dScl{}; r.k.FromBytesLE(curve.Order()); return r }
func (g decaf448) Generator() Element {
	e := curve.Generator()
	e.Double() // Since decaf.Generator() == 2*goldilocks.Generator().
	return &dElt{e}
}

func (g decaf448) RandomElement(rd io.Reader) Element {
	b := make([]byte, fp.Size)
	if n, err := io.ReadFull(rd, b); err != nil || n != len(b) {
		panic(err)
	}
	return g.HashToElement(b, nil)
}

func (g decaf448) RandomScalar(rd io.Reader) Scalar {
	b := make([]byte, fp.Size)
	if n, err := io.ReadFull(rd, b); err != nil || n != len(b) {
		panic(err)
	}
	return g.HashToScalar(b, nil)
}

func (g decaf448) RandomNonZeroScalar(rd io.Reader) Scalar {
	zero := g.NewScalar()
	for {
		s := g.RandomScalar(rd)
		if !s.IsEqual(zero) {
			return s
		}
	}
}

func (g decaf448) HashToElementNonUniform(data, dst []byte) Element {
	return g.HashToElement(data, dst)
}

func (g decaf448) HashToElement(data, dst []byte) Element {
	// Compliaint with draft-irtf-cfrg-hash-to-curve.
	// Appendix C - Hashing to decaf448
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-14#appendix-C
	// SuiteID: decaf448_XOF:SHAKE256_D448MAP_RO_
	var buf [2 * fp.Size]byte
	exp := expander.NewExpanderXOF(xof.SHAKE256, 224, dst)
	uniformBytes := exp.Expand(data, 2*fp.Size)
	copy(buf[:], uniformBytes)
	return g.oneway(&buf)
}

func (g decaf448) HashToScalar(data, dst []byte) Scalar {
	// Section 5.4 - Scalar field
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448-03#section-5.4
	exp := expander.NewExpanderXOF(xof.SHAKE256, 224, dst)
	uniformBytes := exp.Expand(data, 64)
	s := new(dScl)
	s.k.FromBytesLE(uniformBytes)
	return s
}

func (g decaf448) oneway(data *[2 * fp.Size]byte) *dElt {
	// Complaiant with draft-irtf-cfrg-ristretto255-decaf448-03
	// Section 5.3.4 - One-way Map
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448-03#section-5.3.4
	var buf [fp.Size]byte
	copy(buf[:], data[:fp.Size])
	p1 := g.mapFunc(&buf)
	copy(buf[:], data[fp.Size:2*fp.Size])
	p2 := g.mapFunc(&buf)
	p1.Add(&p2)
	return &dElt{p: p1}
}

func (g decaf448) mapFunc(data *[fp.Size]byte) (P curve.Point) {
	t := (*fp.Elt)(data)
	fp.Modp(t)

	one := fp.One()
	d := curve.ParamD()

	r, u0, u1, u2, v := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	tv, sgn, s := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	w0, w1, w2, w3 := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}

	fp.Sqr(r, t)                           // r = -t^2
	fp.Neg(r, r)                           //
	fp.Sub(u0, r, &one)                    // u0 = d * (r-1)
	fp.Mul(u0, u0, &d)                     //
	fp.Add(u1, u0, &one)                   // u1 = (u0 + 1) * (u0 - r)
	fp.Sub(u0, u0, r)                      //
	fp.Mul(u1, u1, u0)                     //
	fp.Add(u2, r, &one)                    // u2 = (r + 1) * u1
	fp.Mul(u2, u2, u1)                     //
	isQR := fp.InvSqrt(v, &aMinusTwoD, u2) // (isQR, v) = sqrt(ONE_MINUS_TWO_D / (r + 1) * u1)
	fp.Mul(tv, t, v)                       // v = CT_SELECT(v IF isQR ELSE t * v)
	fp.Cmov(v, tv, uint(1-isQR))           //
	fp.Neg(sgn, &one)                      //  sgn = CT_SELECT(1 IF isQR ELSE -1)
	fp.Cmov(sgn, &one, uint(isQR))         //
	fp.Add(s, r, &one)                     // s = v * (r + 1)
	fp.Mul(s, s, v)                        //
	ctAbs(w0, s)                           // w0 = 2 * CT_ABS(s)
	fp.Add(w0, w0, w0)                     //
	fp.Sqr(w1, s)                          // w1 = s^2 + 1
	fp.Sub(w2, w1, &one)                   // w2 = s^2 - 1
	fp.Add(w1, w1, &one)                   //
	fp.Sub(w3, r, &one)                    // w3 = v_prime * s * (r - 1) * ONE_MINUS_TWO_D + sgn
	fp.Mul(w3, w3, s)                      //
	fp.Mul(w3, w3, v)                      //
	fp.Mul(w3, w3, &aMinusTwoD)            //
	fp.Add(w3, w3, sgn)                    //
	fp.Mul(&P.X, w0, w3)                   // X = w0 * w3
	fp.Mul(&P.Y, w2, w1)                   // Y = w2 * w1
	fp.Mul(&P.Z, w1, w3)                   // Z = w1 * w3
	P.Ta, P.Tb = *w0, *w2                  // T = w0 * w2

	return P
}

type dElt struct{ p curve.Point }

func (e dElt) String() string                   { return e.p.String() }
func (e *dElt) Set(a Element) Element           { e.p = a.(*dElt).p; return e }
func (e *dElt) Copy() Element                   { return &dElt{e.p} }
func (e *dElt) Add(a, b Element) Element        { e.Set(a); e.p.Add(&b.(*dElt).p); return e }
func (e *dElt) Dbl(a Element) Element           { e.Set(a); e.p.Double(); return e }
func (e *dElt) Neg(a Element) Element           { e.Set(a); e.p.Neg(); return e }
func (e *dElt) Mul(a Element, s Scalar) Element { e.p.ScalarMult(&s.(*dScl).k, &a.(*dElt).p); return e }
func (e *dElt) MulGen(s Scalar) Element {
	k := &s.(*dScl).k
	k2 := &curve.Scalar{}
	k2.Add(k, k) // Since decaf.Generator() == 2*goldilocks.Generator().
	e.p.ScalarBaseMult(k2)
	return e
}

func (e *dElt) IsIdentity() bool {
	// From Decaf, Section 4.5 - Equality
	// In particular, for a curve of cofactor exactly 4,
	// a point (X : Y : Z : T ) is equal to the identity precisely when X = 0.
	return fp.IsZero(&e.p.X) == 1
}

func (e *dElt) IsEqual(a Element) bool {
	// Section 5.3.3 - Equals
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448-03#section-5.3.3
	aa := a.(*dElt)
	l, r := &fp.Elt{}, &fp.Elt{}
	fp.Mul(l, &e.p.X, &aa.p.Y)
	fp.Mul(r, &aa.p.X, &e.p.Y)
	fp.Sub(l, l, r)
	return fp.IsZero(l) == 1
}

func (e *dElt) MarshalBinaryCompress() ([]byte, error) { return e.MarshalBinary() }
func (e *dElt) MarshalBinary() ([]byte, error) {
	var encS [fp.Size]byte
	err := e.marshalBinary(encS[:])
	return encS[:], err
}

func (e *dElt) marshalBinary(enc []byte) error {
	// Section 5.3.2 - Encode
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448-03#section-5.3.2
	x, ta, tb, z := &e.p.X, &e.p.Ta, &e.p.Tb, &e.p.Z
	t, u1, u2, u3 := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	v, ir, rt, w, s := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}

	one := fp.One()
	fp.Mul(t, ta, tb)              // t = ta*tb
	plus, minus := *x, *t          //
	fp.AddSub(&plus, &minus)       // (plus,minus) = (x+t,x-t)
	fp.Mul(u1, &plus, &minus)      // u1 = (x+t)*(x-t)
	fp.Sqr(v, x)                   // v = u1 * ONE_MINUS_D * x0^2
	fp.Mul(v, v, &aMinusD)         //
	fp.Mul(v, v, u1)               //
	_ = fp.InvSqrt(ir, &one, v)    // ir = sqrt(1/v)
	fp.Mul(w, ir, u1)              // rt = CT_ABS(ir * u1 * SQRT_MINUS_D)
	fp.Mul(w, w, &sqrtMinusD)      //
	ctAbs(rt, w)                   //
	fp.Mul(u2, rt, z)              // u2 = INVSQRT_MINUS_D * rt * z0 - t0
	fp.Mul(u2, u2, &invSqrtMinusD) //
	fp.Sub(u2, u2, t)              //
	fp.Mul(u3, x, u2)              // s = CT_ABS(ONE_MINUS_D * ir * x0 * u2)
	fp.Mul(u3, u3, ir)             //
	fp.Mul(u3, u3, &aMinusD)       //
	ctAbs(s, u3)                   //

	return fp.ToBytes(enc[:], s)
}

func (e *dElt) UnmarshalBinary(data []byte) error {
	// Section 5.3.1 - Decode
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448-03#section-5.3.1
	if len(data) < fp.Size {
		return io.ErrShortBuffer
	}

	p := fp.P()
	s := &fp.Elt{}
	copy(s[:], data[:fp.Size])
	isLessThanP := isLessThan(s[:], p[:])
	isPositiveS := 1 - fp.Parity(s)

	one := fp.One()
	paramD := curve.ParamD()

	x, y := &fp.Elt{}, &fp.Elt{}
	ss, u1, u2, u3 := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	ir, v, w := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}

	fp.Sqr(ss, s)                   // ss = s^2
	fp.Add(u1, &one, ss)            // u1 = 1 - a*s^2
	fp.Mul(u2, ss, &paramD)         // u2 = d*s^2
	fp.Add(u2, u2, u2)              //    = 2*d*s^2
	fp.Add(u2, u2, u2)              //    = 4*d*s^2
	fp.Sqr(v, u1)                   // v  = u1^2 = (1 + a*s^2)^2
	fp.Sub(u2, v, u2)               // u2 = u1^2 - 4*d*s^2
	fp.Mul(w, u2, v)                // w  = u2 * u1^2
	isQR := fp.InvSqrt(ir, &one, w) // ir = sqrt(1/(u2 * u1^2))
	fp.Mul(w, s, ir)                // w  = ir*u1
	fp.Mul(w, w, u1)                //    = s*ir*u1
	fp.Mul(w, w, &sqrtMinusD)       //    = s*ir*u1*sqrt(-d)
	fp.Add(w, w, w)                 //    = 2*s*ir*u1*sqrt(-d)
	ctAbs(u3, w)                    // u3 = CT_ABS(w)
	fp.Mul(x, u3, ir)               // x  = u3 * ir * u2 * INVSQRT_MINUS_D
	fp.Mul(x, x, u2)                //
	fp.Mul(x, x, &invSqrtMinusD)    //
	fp.Sub(y, &one, ss)             // y  = (1 - a*s^2) * ir * u1
	fp.Mul(y, y, ir)                //
	fp.Mul(y, y, u1)                //

	b0 := isPositiveS
	b1 := isLessThanP
	b2 := isQR
	b := uint(subtle.ConstantTimeEq(int32(4*b2+2*b1+b0), 0b111))
	fp.Cmov(&e.p.X, x, b)
	fp.Cmov(&e.p.Y, y, b)
	fp.Cmov(&e.p.Ta, x, b)
	fp.Cmov(&e.p.Tb, y, b)
	fp.Cmov(&e.p.Z, &one, b)
	if b == 0 {
		return ErrInvalidDecoding
	}
	return nil
}

type dScl struct{ k curve.Scalar }

func (s *dScl) String() string                 { return s.k.String() }
func (s *dScl) SetUint64(n uint64)             { s.k.SetUint64(n) }
func (s *dScl) Set(a Scalar) Scalar            { s.k = a.(*dScl).k; return s }
func (s *dScl) Copy() Scalar                   { return &dScl{k: s.k} }
func (s *dScl) Add(a, b Scalar) Scalar         { s.k.Add(&a.(*dScl).k, &b.(*dScl).k); return s }
func (s *dScl) Sub(a, b Scalar) Scalar         { s.k.Sub(&a.(*dScl).k, &b.(*dScl).k); return s }
func (s *dScl) Mul(a, b Scalar) Scalar         { s.k.Mul(&a.(*dScl).k, &b.(*dScl).k); return s }
func (s *dScl) Neg(a Scalar) Scalar            { s.k.Neg(&a.(*dScl).k); return s }
func (s *dScl) Inv(a Scalar) Scalar            { s.k.Inv(&a.(*dScl).k); return s }
func (s *dScl) MarshalBinary() ([]byte, error) { return s.k.MarshalBinary() }
func (s *dScl) UnmarshalBinary(b []byte) error { return s.k.UnmarshalBinary(b) }
func (s *dScl) IsEqual(a Scalar) bool          { return s.k.IsEqual(&a.(*dScl).k) == 1 }

func ctAbs(z, x *fp.Elt) {
	minusX := &fp.Elt{}
	fp.Neg(minusX, x)
	*z = *x
	fp.Cmov(z, minusX, uint(fp.Parity(x)))
}

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

var (
	// aMinusD is paramA-paramD = (-1)-(-39081) = 39082.
	aMinusD = fp.Elt{0xaa, 0x98}
	// aMinusTwoD is paramA-2*paramD = (-1)-2*(-39081) = 78163.
	aMinusTwoD = fp.Elt{0x53, 0x31, 0x01}
	// sqrtMinusD is the smallest root of sqrt(paramD) = sqrt(39081).
	sqrtMinusD = fp.Elt{
		0x36, 0x27, 0x57, 0x45, 0x0f, 0xef, 0x42, 0x96,
		0x52, 0xce, 0x20, 0xaa, 0xf6, 0x7b, 0x33, 0x60,
		0xd2, 0xde, 0x6e, 0xfd, 0xf4, 0x66, 0x9a, 0x83,
		0xba, 0x14, 0x8c, 0x96, 0x80, 0xd7, 0xa2, 0x64,
		0x4b, 0xd5, 0xb8, 0xa5, 0xb8, 0xa7, 0xf1, 0xa1,
		0xa0, 0x6a, 0xa2, 0x2f, 0x72, 0x8d, 0xf6, 0x3b,
		0x68, 0xf7, 0x24, 0xeb, 0xfb, 0x62, 0xd9, 0x22,
	}
	// invSqrtMinusD is the smallest root of sqrt(1/paramD) = sqrt(1/39081).
	invSqrtMinusD = fp.Elt{
		0x2c, 0x68, 0x78, 0xb8, 0x5e, 0xbb, 0xaf, 0x53,
		0xf3, 0x94, 0x9e, 0xf1, 0x79, 0x24, 0xbb, 0xef,
		0x15, 0xba, 0x1f, 0xc2, 0xe2, 0x7e, 0x70, 0xbe,
		0x1a, 0x52, 0xa6, 0x28, 0xf1, 0x56, 0xba, 0xd6,
		0xa7, 0x27, 0x5b, 0x3a, 0x0c, 0x95, 0x90, 0x5a,
		0x07, 0xc8, 0xca, 0x0b, 0x5a, 0xe3, 0x2b, 0x90,
		0x57, 0xc0, 0x22, 0xe2, 0x52, 0x06, 0xf4, 0x6e,
	}
)
