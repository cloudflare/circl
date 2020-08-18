package ted448

import (
	"crypto/subtle"
	"fmt"

	fp "github.com/cloudflare/circl/math/fp448"
)

// Point defines a point on the ted448 curve using extended projective
// coordinates. Thus, for any affine point (x,y) it holds x=X/Z, y = Y/Z, and
// T = Ta*Tb = X*Y/Z.
type Point struct{ X, Y, Z, Ta, Tb fp.Elt }

type prePointAffine struct{ addYX, subYX, dt2 fp.Elt }

type prePointProy struct {
	prePointAffine
	z2 fp.Elt
}

func (P Point) String() string {
	return fmt.Sprintf("x: %v\ny: %v\nta: %v\ntb: %v\nz: %v", P.X, P.Y, P.Ta, P.Tb, P.Z)
}

// cneg conditionally negates the point if b=1.
func (P *Point) cneg(b uint) {
	t := &fp.Elt{}
	fp.Neg(t, &P.X)
	fp.Cmov(&P.X, t, b)
	fp.Neg(t, &P.Ta)
	fp.Cmov(&P.Ta, t, b)
}

// Double updates P with 2P.
func (P *Point) Double() {
	// This is formula (7) from "Twisted Edwards Curves Revisited" by
	// Hisil H., Wong K.KH., Carter G., Dawson E. (2008)
	// https://doi.org/10.1007/978-3-540-89255-7_20
	Px, Py, Pz, Pta, Ptb := &P.X, &P.Y, &P.Z, &P.Ta, &P.Tb
	a, b, c, e, f, g, h := Px, Py, Pz, Pta, Px, Py, Ptb
	fp.Add(e, Px, Py) // x+y
	fp.Sqr(a, Px)     // A = x^2
	fp.Sqr(b, Py)     // B = y^2
	fp.Sqr(c, Pz)     // z^2
	fp.Add(c, c, c)   // C = 2*z^2
	fp.Add(h, a, b)   // H = A+B
	fp.Sqr(e, e)      // (x+y)^2
	fp.Sub(e, e, h)   // E = (x+y)^2-A-B
	fp.Sub(g, b, a)   // G = B-A
	fp.Sub(f, c, g)   // F = C-G
	fp.Mul(Pz, f, g)  // Z = F * G
	fp.Mul(Px, e, f)  // X = E * F
	fp.Mul(Py, g, h)  // Y = G * H, T = E * H
}

// mixAdd calulates P= P+Q, where Q is a precomputed448 point with Z_Q = 1.
func (P *Point) mixAddZ1(Q *prePointAffine) {
	fp.Add(&P.Z, &P.Z, &P.Z) // D = 2*z1 (z2=1)
	P.coreAddition(Q)
}

// coreAddition calculates P=P+Q for curves with A=-1.
func (P *Point) coreAddition(Q *prePointAffine) {
	// Formula as in Eq.(5) of "Twisted Edwards Curves Revisited" by
	// Hisil H., Wong K.KH., Carter G., Dawson E. (2008)
	// https://doi.org/10.1007/978-3-540-89255-7_20
	Px, Py, Pz, Pta, Ptb := &P.X, &P.Y, &P.Z, &P.Ta, &P.Tb
	addYX2, subYX2, dt2 := &Q.addYX, &Q.subYX, &Q.dt2
	a, b, c, d, e, f, g, h := Px, Py, &fp.Elt{}, Pz, Pta, Px, Py, Ptb
	fp.Mul(c, Pta, Ptb)  // t1 = ta*tb
	fp.Sub(h, Py, Px)    // y1-x1
	fp.Add(b, Py, Px)    // y1+x1
	fp.Mul(a, h, subYX2) // A = (y1-x1)*(y2-x2)
	fp.Mul(b, b, addYX2) // B = (y1+x1)*(y2+x2)
	fp.Mul(c, c, dt2)    // C = 2*D*t1*t2
	fp.Sub(e, b, a)      // E = B-A
	fp.Add(h, b, a)      // H = B+A
	fp.Sub(f, d, c)      // F = D-C
	fp.Add(g, d, c)      // G = D+C
	fp.Mul(Pz, f, g)     // Z = F * G
	fp.Mul(Px, e, f)     // X = E * F
	fp.Mul(Py, g, h)     // Y = G * H, T = E * H
}

func (P *prePointAffine) neg() {
	P.addYX, P.subYX = P.subYX, P.addYX
	fp.Neg(&P.dt2, &P.dt2)
}

func (P *prePointAffine) cneg(b int) {
	t := &fp.Elt{}
	fp.Cswap(&P.addYX, &P.subYX, uint(b))
	fp.Neg(t, &P.dt2)
	fp.Cmov(&P.dt2, t, uint(b))
}

func (P *prePointAffine) cmov(Q *prePointAffine, b uint) {
	fp.Cmov(&P.addYX, &Q.addYX, b)
	fp.Cmov(&P.subYX, &Q.subYX, b)
	fp.Cmov(&P.dt2, &Q.dt2, b)
}

// mixAdd calculates P= P+Q, where Q is a precomputed448 point with Z_Q != 1.
func (P *Point) mixAdd(Q *prePointProy) {
	fp.Mul(&P.Z, &P.Z, &Q.z2) // D = 2*z1*z2
	P.coreAddition(&Q.prePointAffine)
}

// IsIdentity returns True is P is the identity.
func (P *Point) IsIdentity() bool {
	b0 := fp.IsZero(&P.X)
	b1 := 1 - fp.IsZero(&P.Y)
	b2 := 1 - fp.IsZero(&P.Z)
	b3 := fp.IsEqual(&P.Y, &P.Z)
	return subtle.ConstantTimeEq(int32(8*b3+4*b2+2*b1+b0), 0xF) == 1
}

// IsEqual returns True if P is equivalent to Q.
func (P *Point) IsEqual(Q *Point) bool {
	l, r := &fp.Elt{}, &fp.Elt{}
	fp.Mul(l, &P.X, &Q.Z)
	fp.Mul(r, &Q.X, &P.Z)
	fp.Sub(l, l, r)
	b0 := fp.IsZero(l)
	fp.Mul(l, &P.Y, &Q.Z)
	fp.Mul(r, &Q.Y, &P.Z)
	fp.Sub(l, l, r)
	b1 := fp.IsZero(l)
	fp.Mul(l, &P.Ta, &P.Tb)
	fp.Mul(l, l, &Q.Z)
	fp.Mul(r, &Q.Ta, &Q.Tb)
	fp.Mul(r, r, &P.Z)
	fp.Sub(l, l, r)
	b2 := fp.IsZero(l)
	return subtle.ConstantTimeEq(int32(4*b2+2*b1+b0), 0x7) == 1
}

// Neg obtains the inverse of P.
func (P *Point) Neg() { fp.Neg(&P.X, &P.X); fp.Neg(&P.Ta, &P.Ta) }

// Add calculates P = P+Q.
func (P *Point) Add(Q *Point) {
	preB := &prePointProy{}
	preB.FromPoint(Q)
	P.mixAdd(preB)
}

// oddMultiples calculates T[i] = (2*i-1)P for 0 < i < len(T).
func (P *Point) oddMultiples(T []prePointProy) {
	if n := len(T); n > 0 {
		Q := *P
		T[0].FromPoint(&Q)
		_2P := *P
		_2P.Double()
		R := &prePointProy{}
		R.FromPoint(&_2P)
		for i := 1; i < n; i++ {
			Q.mixAdd(R)
			T[i].FromPoint(&Q)
		}
	}
}

// cmov conditionally moves Q into P if b=1.
func (P *prePointProy) cmov(Q *prePointProy, b uint) {
	P.prePointAffine.cmov(&Q.prePointAffine, b)
	fp.Cmov(&P.z2, &Q.z2, b)
}

// FromPoint precomputes some coordinates of Q for mised addition.
func (P *prePointProy) FromPoint(Q *Point) {
	fp.Add(&P.addYX, &Q.Y, &Q.X)    // addYX = X + Y
	fp.Sub(&P.subYX, &Q.Y, &Q.X)    // subYX = Y - X
	fp.Mul(&P.dt2, &Q.Ta, &Q.Tb)    // T = ta*tb
	fp.Mul(&P.dt2, &P.dt2, &paramD) // D*T
	fp.Add(&P.dt2, &P.dt2, &P.dt2)  // dt2 = 2*D*T
	fp.Add(&P.z2, &Q.Z, &Q.Z)       // z2 = 2*Z
}
