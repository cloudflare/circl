package p384

import (
	"math/big"
)

type affinePoint struct {
	x, y fp384
}

func newAffinePoint(X, Y *big.Int) *affinePoint {
	x, y := &fp384{}, &fp384{}
	copy(x[:], X.Bits())
	copy(y[:], Y.Bits())

	montEncode(x, x)
	montEncode(y, y)

	return &affinePoint{*x, *y}
}

func (ap *affinePoint) ToJacobian() *jacobianPoint {
	return &jacobianPoint{ap.x, ap.y, *newFp384(1)}
}

func (ap *affinePoint) ToInt() (*big.Int, *big.Int) {
	x, y := &fp384{}, &fp384{}
	*x, *y = ap.x, ap.y

	montDecode(x, x)
	montDecode(y, y)

	return x.Int(), y.Int()
}

func (ap *affinePoint) IsZero() bool {
	zero := fp384{}
	return ap.x == zero && ap.y == zero
}

type jacobianPoint struct {
	x, y, z fp384
}

func (jp *jacobianPoint) ToAffine() *affinePoint {
	if jp.IsZero() {
		return &affinePoint{}
	}

	z := &fp384{}
	*z = jp.z
	z.Invert(z)

	x, y := &fp384{}, &fp384{}
	*x, *y = jp.x, jp.y

	fp384Mul(x, x, z)
	fp384Mul(x, x, z)
	fp384Mul(y, y, z)
	fp384Mul(y, y, z)
	fp384Mul(y, y, z)

	return &affinePoint{*x, *y}
}

func (jp *jacobianPoint) IsZero() bool {
	zero := fp384{}
	return jp.z == zero
}

func (jp *jacobianPoint) Dup() *jacobianPoint {
	return &jacobianPoint{jp.x, jp.y, jp.z}
}
