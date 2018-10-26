package p384

import (
	"math/big"
)

type affinePoint struct {
	x, y gfP
}

func newAffinePoint(X, Y *big.Int) *affinePoint {
	x, y := &gfP{}, &gfP{}
	copy(x[:], X.Bits())
	copy(y[:], Y.Bits())

	montEncode(x, x)
	montEncode(y, y)

	return &affinePoint{*x, *y}
}

func (ap *affinePoint) ToJacobian() *jacobianPoint {
	return &jacobianPoint{ap.x, ap.y, *newGFp(1)}
}

func (ap *affinePoint) ToInt() (*big.Int, *big.Int) {
	x, y := &gfP{}, &gfP{}
	*x, *y = ap.x, ap.y

	montDecode(x, x)
	montDecode(y, y)

	return x.Int(), y.Int()
}

func (ap *affinePoint) IsZero() bool {
	zero := gfP{}
	return ap.x == zero && ap.y == zero
}

type jacobianPoint struct {
	x, y, z gfP
}

func (jp *jacobianPoint) ToAffine() *affinePoint {
	if jp.IsZero() {
		return &affinePoint{}
	}

	z := &gfP{}
	*z = jp.z
	z.Invert(z)

	x, y := &gfP{}, &gfP{}
	*x, *y = jp.x, jp.y

	gfpMul(x, x, z)
	gfpMul(x, x, z)
	gfpMul(y, y, z)
	gfpMul(y, y, z)
	gfpMul(y, y, z)

	return &affinePoint{*x, *y}
}

func (jp *jacobianPoint) IsZero() bool {
	zero := gfP{}
	return jp.z == zero
}

func (jp *jacobianPoint) Dup() *jacobianPoint {
	return &jacobianPoint{jp.x, jp.y, jp.z}
}
