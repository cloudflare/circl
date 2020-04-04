package goldilocks

import (
	"fmt"

	"github.com/cloudflare/circl/internal/conv"
	fp "github.com/cloudflare/circl/math/fp448"
)

// Curve is the Goldilocks curve x^2+y^2=z^2-39081x^2y^2.
type Curve struct{}

// Identity returns the identity point.
func (Curve) Identity() *Point {
	return &Point{
		y: fp.One(),
		z: fp.One(),
	}
}

// IsOnCurve returns true if the point lies on the curve.
func (Curve) IsOnCurve(P *Point) bool {
	x2, y2, t, t2, z2 := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	rhs, lhs := &fp.Elt{}, &fp.Elt{}
	fp.Mul(t, &P.ta, &P.tb)  // t = ta*tb
	fp.Sqr(x2, &P.x)         // x^2
	fp.Sqr(y2, &P.y)         // y^2
	fp.Sqr(z2, &P.z)         // y^2
	fp.Sqr(t2, t)            // t^2
	fp.Add(lhs, x2, y2)      // x^2 + y^2
	fp.Mul(rhs, t2, &paramD) // dt^2
	fp.Add(rhs, rhs, z2)     // z^2 + dt^2
	fp.Sub(lhs, lhs, rhs)    // x^2 + y^2 - (z^2 + dt^2)
	eq0 := fp.IsZero(lhs)

	fp.Mul(lhs, &P.x, &P.y) // xy
	fp.Mul(rhs, t, &P.z)    // tz
	fp.Sub(lhs, lhs, rhs)   // xy - tz
	eq1 := fp.IsZero(lhs)
	return eq0 && eq1
}

// Generator returns the generator point.
func (Curve) Generator() *Point {
	return &Point{
		x:  genX,
		y:  genY,
		z:  fp.One(),
		ta: genX,
		tb: genY,
	}
}

// Double returns 2P.
func (Curve) Double(P *Point) *Point { R := *P; R.Double(); return &R }

// Add returns P+Q.
func (Curve) Add(P, Q *Point) *Point { R := *P; R.Add(Q); return &R }

// ScalarMult returns kP.
func (e Curve) ScalarMult(k []byte, P *Point) *Point {
	div4(k[:])
	return e.pull(twistCurve{}.ScalarMult(k, e.push(P)))
}

// ScalarBaseMult returns kG where G is the generator point.
func (e Curve) ScalarBaseMult(k []byte) *Point {
	var scalar [ScalarSize]byte
	reduceModOrder(scalar[:], k)
	fmt.Printf("k: %v\n", conv.BytesLe2Hex(scalar[:]))
	// div4(scalar[:])
	P := twistCurve{}.ScalarBaseMult(scalar[:])
	P.ToAffine()
	fmt.Printf("Q:\n%v\n", P)
	return e.pull(P)
}

// CombinedMult returns mG+nP.
func (e Curve) CombinedMult(m, n []byte, P *Point) *Point {
	div4(m[:])
	div4(n[:])
	return e.pull(twistCurve{}.CombinedMult(m, n, e.push(P)))
}
