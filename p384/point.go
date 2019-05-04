package p384

import (
	"math/big"
)

type affinePoint struct{ x, y fp384 }

func newAffinePoint(X, Y *big.Int) *affinePoint {
	var P affinePoint
	montEncode(&P.x, fp384Set(X))
	montEncode(&P.y, fp384Set(Y))
	return &P
}

func (ap *affinePoint) toJacobian() *jacobianPoint {
	var P jacobianPoint
	P.x = ap.x
	P.y = ap.y
	montEncode(&P.z, &fp384{1})
	return &P
}

func (ap *affinePoint) toInt() (*big.Int, *big.Int) {
	x, y := &fp384{}, &fp384{}
	montDecode(x, &ap.x)
	montDecode(y, &ap.y)
	return x.BigInt(), y.BigInt()
}

func (ap *affinePoint) isZero() bool {
	zero := fp384{}
	return ap.x == zero && ap.y == zero
}

type jacobianPoint struct {
	x, y, z fp384
}

func (jp *jacobianPoint) toAffine() *affinePoint {
	var P affinePoint
	z, z2 := &fp384{}, &fp384{}
	fp384Inv(z, &jp.z)
	fp384Sqr(z2, z)
	fp384Mul(&P.x, &jp.x, z2)
	fp384Mul(&P.y, &jp.y, z)
	fp384Mul(&P.y, &P.y, z2)
	return &P
}

func (jp *jacobianPoint) isZero() bool { return jp.z == fp384{} }

func (jp *jacobianPoint) dup() *jacobianPoint { return &jacobianPoint{jp.x, jp.y, jp.z} }
