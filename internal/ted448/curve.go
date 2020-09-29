// Package ted448 provides operations on a twist curve of the Goldilocks curve.
//
// The twist curve is defined over Fp = GF(2^448-2^224-1) as
//  ted448: ax^2+y^2 = 1 + dx^2y^2, where a=-1 and d=-39082.
// The ted448 curve provides fast arithmetic operations due to a=-1.
//
// Isogenies
//
// The ted448 curve is 4-degree isogeneous to the Goldilocks curve, and the
// explicit map Iso4 is given in [Ham, Sec 2].
//
// The ted448 curve is 2-degree isogeneous to the Jacobi quartic used in Decaf.
//
// Generator Point
//
// The generator of ted448 is returned by Generator(), and is equal to
// Iso4(Gx,Gy), where (Gx,Gy) is the generator of the Goldilocks curve.
//
// References
//
// [Ham] Twisting Edwards curves with isogenies, Hamburg. (https://www.shiftleft.org/papers/isogeny)
//
// [RFC7748] Elliptic Curves for Security (https://rfc-editor.org/rfc/rfc7748.txt)
package ted448

import (
	"crypto/subtle"
	"math/bits"

	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/math"
	fp "github.com/cloudflare/circl/math/fp448"
)

// Identity returns the identity point.
func Identity() Point { return Point{Y: fp.One(), Z: fp.One()} }

// Generator returns the generator point.
func Generator() Point { return Point{X: genX, Y: genY, Z: fp.One(), Ta: genX, Tb: genY} }

// Order returns the number of points in the prime subgroup.
func Order() Scalar { return order }

// ParamD returns the number of points in the prime subgroup.
func ParamD() fp.Elt { return paramD }

// IsOnCurve returns true if the point lies on the curve.
func IsOnCurve(P *Point) bool {
	eq0 := fp.IsZero(&P.X)
	eq0 &= fp.IsZero(&P.Y)
	eq0 &= fp.IsZero(&P.Z)
	eq0 &= fp.IsZero(&P.Ta)
	eq0 &= fp.IsZero(&P.Tb)
	eq0 = 1 - eq0
	x2, y2, t, t2, z2 := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	rhs, lhs := &fp.Elt{}, &fp.Elt{}
	fp.Mul(t, &P.Ta, &P.Tb)  // t = ta*tb
	fp.Sqr(x2, &P.X)         // x^2
	fp.Sqr(y2, &P.Y)         // y^2
	fp.Sqr(z2, &P.Z)         // z^2
	fp.Sqr(t2, t)            // t^2
	fp.Sub(lhs, y2, x2)      // -x^2 + y^2, since a=-1
	fp.Mul(rhs, t2, &paramD) // dt^2
	fp.Add(rhs, rhs, z2)     // z^2 + dt^2
	fp.Sub(lhs, lhs, rhs)    // ax^2 + y^2 - (z^2 + dt^2)
	eq1 := fp.IsZero(lhs)
	fp.Mul(lhs, &P.X, &P.Y) // xy
	fp.Mul(rhs, t, &P.Z)    // tz
	fp.Sub(lhs, lhs, rhs)   // xy - tz
	eq2 := fp.IsZero(lhs)
	return subtle.ConstantTimeByteEq(byte(4*eq2+2*eq1+eq0), 0x7) == 1
}

// subYDiv16 update x = (x - y) / 16.
func subYDiv16(x *scalar64, y int64) {
	s := uint64(y >> 63)
	x0, b0 := bits.Sub64((*x)[0], uint64(y), 0)
	x1, b1 := bits.Sub64((*x)[1], s, b0)
	x2, b2 := bits.Sub64((*x)[2], s, b1)
	x3, b3 := bits.Sub64((*x)[3], s, b2)
	x4, b4 := bits.Sub64((*x)[4], s, b3)
	x5, b5 := bits.Sub64((*x)[5], s, b4)
	x6, _ := bits.Sub64((*x)[6], s, b5)
	x[0] = (x0 >> 4) | (x1 << 60)
	x[1] = (x1 >> 4) | (x2 << 60)
	x[2] = (x2 >> 4) | (x3 << 60)
	x[3] = (x3 >> 4) | (x4 << 60)
	x[4] = (x4 >> 4) | (x5 << 60)
	x[5] = (x5 >> 4) | (x6 << 60)
	x[6] = (x6 >> 4)
}

func recodeScalar(d *[113]int8, k *scalar64) {
	for i := 0; i < 112; i++ {
		d[i] = int8((k[0] & 0x1f) - 16)
		subYDiv16(k, int64(d[i]))
	}
	d[112] = int8(k[0])
}

// ScalarMult calculates R = kP.
func ScalarMult(R *Point, k *Scalar, P *Point) {
	var TabP [8]prePointProy
	var S prePointProy
	var d [113]int8

	var k64, _k64, order64 scalar64
	k64.fromScalar(k)
	order64.fromScalar(&order)
	k64.cmov(&order64, uint64(k64.isZero()))

	isEven := 1 - int(k64[0]&0x1)
	_k64.sub(&order64, &k64)
	k64.cmov(&_k64, uint64(isEven))

	recodeScalar(&d, &k64)

	P.oddMultiples(TabP[:])
	Q := Identity()
	for i := 112; i >= 0; i-- {
		Q.Double()
		Q.Double()
		Q.Double()
		Q.Double()
		mask := d[i] >> 7
		absDi := (d[i] + mask) ^ mask
		inx := int32((absDi - 1) >> 1)
		sig := int((d[i] >> 7) & 0x1)
		for j := range TabP {
			S.cmov(&TabP[j], uint(subtle.ConstantTimeEq(inx, int32(j))))
		}
		S.cneg(sig)
		Q.mixAdd(&S)
	}
	Q.cneg(uint(isEven))
	*R = Q
}

const (
	omegaFix = 7
	omegaVar = 5
)

// CombinedMult calculates R = mG+nP using a non-constant-time procedure.
func CombinedMult(R *Point, m, n *Scalar, P *Point) {
	nafFix := math.OmegaNAF(conv.BytesLe2BigInt(m[:]), omegaFix)
	nafVar := math.OmegaNAF(conv.BytesLe2BigInt(n[:]), omegaVar)

	if len(nafFix) > len(nafVar) {
		nafVar = append(nafVar, make([]int32, len(nafFix)-len(nafVar))...)
	} else if len(nafFix) < len(nafVar) {
		nafFix = append(nafFix, make([]int32, len(nafVar)-len(nafFix))...)
	}

	var TabQ [1 << (omegaVar - 2)]prePointProy
	P.oddMultiples(TabQ[:])
	Q := Identity()
	for i := len(nafFix) - 1; i >= 0; i-- {
		Q.Double()
		// Generator point
		if nafFix[i] != 0 {
			idxM := absolute(nafFix[i]) >> 1
			R := tabVerif[idxM]
			if nafFix[i] < 0 {
				R.neg()
			}
			Q.mixAddZ1(&R)
		}
		// Variable input point
		if nafVar[i] != 0 {
			idxN := absolute(nafVar[i]) >> 1
			S := TabQ[idxN]
			if nafVar[i] < 0 {
				S.neg()
			}
			Q.mixAdd(&S)
		}
	}
	*R = Q
}

// absolute returns always a positive value.
func absolute(x int32) int32 {
	mask := x >> 31
	return (x + mask) ^ mask
}
