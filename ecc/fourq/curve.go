package fourq

import (
	"math/big"

	"github.com/cloudflare/circl/internal/conv"
)

// Size of scalars used for point multiplication.
const Size = 32

// Point represents an affine point of the curve. The identity is (0,1).
type Point struct{ X, Y Fq }

// CurveParams contains the parameters of the elliptic curve.
type CurveParams struct {
	Name string   // The canonical name of the curve.
	P    *big.Int // The order of the underlying field Fp.
	N    *big.Int // The order of the generator point.
	G    Point    // This is the generator point.
}

// Params returns the parameters for the curve.
func Params() *CurveParams {
	params := CurveParams{Name: "FourQ"}
	params.P = conv.Uint64Le2BigInt(prime[:])
	params.N = conv.Uint64Le2BigInt(orderGenerator[:])
	params.G.X = genX
	params.G.Y = genY
	return &params
}

// IsOnCurve reports whether the given P=(x,y) lies on the curve.
func (P *Point) IsOnCurve() bool {
	var _P pointR1
	P.toR1(&_P)
	return _P.IsOnCurve()
}

// SetGenerator assigns to P the generator point G.
func (P *Point) SetGenerator() { P.X = genX; P.Y = genY }

// SetIdentity assigns to P the identity element.
func (P *Point) SetIdentity() {
	var _P pointR1
	_P.SetIdentity()
	P.fromR1(&_P)
}

// IsIdentity returns true if P is the identity element.
func (P *Point) IsIdentity() bool {
	var _P pointR1
	P.toR1(&_P)
	return _P.IsIdentity()
}

// Add calculates a point addition P = Q + R.
func (P *Point) Add(Q, R *Point) {
	var _Q, _R pointR1
	var _R2 pointR2
	Q.toR1(&_Q)
	R.toR1(&_R)
	_R2.FromR1(&_R)
	_Q.add(&_R2)
	P.fromR1(&_Q)
}

// ScalarMult calculates P = k*Q, where Q is an N-torsion point.
func (P *Point) ScalarMult(k *[Size]byte, Q *Point) {
	var _P, _Q pointR1
	Q.toR1(&_Q)
	_Q.ClearCofactor()
	_P.ScalarMult(k, &_Q)
	P.fromR1(&_P)
}

// ScalarBaseMult calculates P = k*G, where G is the generator point.
func (P *Point) ScalarBaseMult(k *[Size]byte) {
	var _P pointR1
	_P.ScalarBaseMult(k)
	P.fromR1(&_P)
}

func (P *Point) fromR1(Q *pointR1) {
	Q.ToAffine()
	P.X = Q.X
	P.Y = Q.Y
}

func (P *Point) toR1(projP *pointR1) {
	projP.X = P.X
	projP.Y = P.Y
	projP.Ta = P.X
	projP.Tb = P.Y
	projP.Z.setOne()
}
