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

// ScalarMult2 calculates P = k*Q, where Q is an N-torsion point. Allows for not clearing the cofactor.
func (P *Point) ScalarMult2(k *[Size]byte, Q *Point, clearCofactor bool) {
	var _P, _Q pointR1
	Q.toR1(&_Q)

	if clearCofactor {
		_Q.ClearCofactor()
	}
	_P.ScalarMult(k, &_Q)
	P.fromR1(&_P)
}

// DoubleScalarMult calculates P = k*G + l*Q, where the G is the generator.
func (P *Point) DoubleScalarMult(k *[Size]byte, Q *Point, l *[Size]byte) {

	//Based on FourQLib's no endomorphism ecc_mul_double:

	/*
		point_t A;
		point_extproj_t T;
		point_extproj_precomp_t S;

		if (ecc_mul(Q, l, A, false) == false) {
			return false;
		}
		point_setup(A, T);
		R1_to_R2(T, S);

		ecc_mul_fixed(k, A);
		point_setup(A, T);
		eccadd(S, T);
		eccnorm(T, R);
	*/

	var _A Point
	var _T pointR1
	var _S pointR2

	// _A = q * l, don't clear cofactor
	_A.ScalarMult2(l, Q, false)

	// _A -> _T
	_A.toR1(&_T)

	// _T -> _S
	_S.FromR1(&_T)

	// _A = k * G
	_A.ScalarBaseMult(k)

	// _A -> _T
	_A.toR1(&_T)

	// _T = _T * _S
	_T.add(&_S)

	P.fromR1(&_T)
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
