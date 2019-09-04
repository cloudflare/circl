// +build arm64 amd64

package p384

import (
	"crypto/elliptic"
	"crypto/subtle"
	"math/big"

	"github.com/cloudflare/circl/math"
)

// Curve is used to provide the extended functionality and performance of
// elliptic.Curve interface.
type Curve interface {
	elliptic.Curve
	// IsAtInfinity returns True is the point is the identity point.
	IsAtInfinity(X, Y *big.Int) bool
	// CombinedMult calculates P=mG+nQ, where G is the generator and
	// Q=(Qx,Qy). The scalars m and n are positive integers in big-endian form.
	// Runs in non-constant time to be used in signature verification.
	CombinedMult(Qx, Qy *big.Int, m, n []byte) (Px, Py *big.Int)
}

// P384 returns a Curve which implements P-384 (see FIPS 186-3, section D.2.4).
func P384() Curve { return p384 }

type curve struct{ *elliptic.CurveParams }

var p384 curve

func init() {
	p384.CurveParams = elliptic.P384().Params()
}

// IsAtInfinity returns True is the point is the identity point.
func (c curve) IsAtInfinity(X, Y *big.Int) bool {
	return X.Sign() == 0 && Y.Sign() == 0
}

// IsOnCurve reports whether the given (x,y) lies on the curve.
func (c curve) IsOnCurve(X, Y *big.Int) bool {
	// bMon is the curve's B parameter encoded. bMon = B*R mod p.
	bMon := &fp384{
		0xcc, 0x2d, 0x41, 0x9d, 0x71, 0x88, 0x11, 0x08,
		0xec, 0x32, 0x4c, 0x7a, 0xd8, 0xad, 0x29, 0xf7,
		0x2e, 0x02, 0x20, 0x19, 0x9b, 0x20, 0xf2, 0x77,
		0xe2, 0x8a, 0x93, 0x94, 0xee, 0x4b, 0x37, 0xe3,
		0x94, 0x20, 0x02, 0x1f, 0xf4, 0x21, 0x2b, 0xb6,
		0xf9, 0xbf, 0x4f, 0x60, 0x4b, 0x11, 0x08, 0xcd,
	}
	x, y := &fp384{}, &fp384{}
	x.SetBigInt(X)
	y.SetBigInt(Y)
	montEncode(x, x)
	montEncode(y, y)

	y2, x3 := &fp384{}, &fp384{}
	fp384Sqr(y2, y)
	fp384Sqr(x3, x)
	fp384Mul(x3, x3, x)

	threeX := &fp384{}
	fp384Add(threeX, x, x)
	fp384Add(threeX, threeX, x)

	fp384Sub(x3, x3, threeX)
	fp384Add(x3, x3, bMon)

	return *y2 == *x3
}

// Add returns the sum of (x1,y1) and (x2,y2)
func (c curve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	P := newAffinePoint(x1, y1).toJacobian()
	P.mixadd(P, newAffinePoint(x2, y2))
	return P.toAffine().toInt()
}

// Double returns 2*(x,y)
func (c curve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	P := newAffinePoint(x1, y1).toJacobian()
	P.double()
	return P.toAffine().toInt()
}

// reduceScalar shorten a scalar modulo the order of the curve.
func (c curve) reduceScalar(k []byte) []byte {
	const max = sizeFp
	if len(k) > max {
		bigK := new(big.Int).SetBytes(k)
		bigK.Mod(bigK, c.Params().N)
		k = bigK.Bytes()
	}
	if len(k) < max {
		k = append(make([]byte, max-len(k)), k...)
	}
	return k
}

// toOdd performs k = (-k mod N) if k is even.
func (c curve) toOdd(k []byte) ([]byte, int) {
	var X, Y big.Int
	X.SetBytes(k)
	Y.Neg(&X).Mod(&Y, c.Params().N)
	isEven := 1 - int(X.Bit(0))
	x := X.Bytes()
	y := Y.Bytes()

	if len(x) < len(y) {
		x = append(make([]byte, len(y)-len(x)), x...)
	} else if len(x) > len(y) {
		y = append(make([]byte, len(x)-len(y)), y...)
	}
	subtle.ConstantTimeCopy(isEven, x, y)
	return x, isEven
}

// ScalarMult returns (Qx,Qy)=k*(Px,Py) where k is a number in big-endian form.
func (c curve) ScalarMult(Px, Py *big.Int, k []byte) (Qx, Qy *big.Int) {
	const omega = uint(5)
	k = c.reduceScalar(k)
	oddK, isEvenK := c.toOdd(k)

	var scalar big.Int
	scalar.SetBytes(oddK)
	if scalar.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}
	L := math.SignedDigit(&scalar, omega, uint(c.CurveParams.N.BitLen()))

	var R jacobianPoint
	Q := zeroPoint().toJacobian()
	TabP := newAffinePoint(Px, Py).oddMultiples(omega)
	for i := len(L) - 1; i > 0; i-- {
		for j := uint(0); j < omega-1; j++ {
			Q.double()
		}
		idx := absolute(L[i]) >> 1
		for j := range TabP {
			R.cmov(&TabP[j], subtle.ConstantTimeEq(int32(j), idx))
		}
		R.cneg(int(L[i]>>31) & 1)
		Q.add(Q, &R)
	}
	for j := uint(0); j < omega-1; j++ {
		Q.double()
	}
	idx := absolute(L[0]) >> 1
	for j := range TabP {
		R.cmov(&TabP[j], subtle.ConstantTimeEq(int32(j), idx))
	}
	R.cneg(int(L[0]>>31) & 1)
	QQ := Q.toHomogeneous()
	QQ.completeAdd(QQ, R.toHomogeneous())
	QQ.cneg(isEvenK)
	return QQ.toAffine().toInt()
}

// ScalarBaseMult returns k*G, where G is the base point of the group
// and k is an integer in big-endian form.
func (c curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return c.ScalarMult(c.Params().Gx, c.Params().Gy, k)
}

// CombinedMult calculates P=mG+nQ, where G is the generator and Q=(x,y,z).
// The scalars m and n are integers in big-endian form. Non-constant time.
func (c curve) CombinedMult(Qx, Qy *big.Int, m, n []byte) (Px, Py *big.Int) {
	const nOmega = uint(5)
	var k big.Int
	k.SetBytes(m)
	nafM := math.OmegaNAF(&k, baseOmega)
	k.SetBytes(n)
	nafN := math.OmegaNAF(&k, nOmega)

	if len(nafM) > len(nafN) {
		nafN = append(nafN, make([]int32, len(nafM)-len(nafN))...)
	} else if len(nafM) < len(nafN) {
		nafM = append(nafM, make([]int32, len(nafN)-len(nafM))...)
	}

	TabQ := newAffinePoint(Qx, Qy).oddMultiples(nOmega)
	var jR jacobianPoint
	var aR affinePoint
	P := zeroPoint().toJacobian()
	for i := len(nafN) - 1; i >= 0; i-- {
		P.double()
		// Generator point
		if nafM[i] != 0 {
			idxM := absolute(nafM[i]) >> 1
			aR = baseOddMultiples[idxM]
			if nafM[i] < 0 {
				aR.neg()
			}
			P.mixadd(P, &aR)
		}
		// Input point
		if nafN[i] != 0 {
			idxN := absolute(nafN[i]) >> 1
			jR = TabQ[idxN]
			if nafN[i] < 0 {
				jR.neg()
			}
			P.add(P, &jR)
		}
	}
	return P.toAffine().toInt()
}

// absolute returns always a positive value.
func absolute(x int32) int32 {
	mask := x >> 31
	return (x + mask) ^ mask
}
