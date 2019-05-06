// Package p384 is an optimized P-384 implementation.
package p384

import (
	ecc "crypto/elliptic"
	"math/big"
	"sync"

	"github.com/cloudflare/circl/math"
)

var (
	// bMon is the curve's B parameter encoded. bMon = B*R mod p.
	bMon = fp384{
		0xcc, 0x2d, 0x41, 0x9d, 0x71, 0x88, 0x11, 0x08, 0xec, 0x32, 0x4c, 0x7a,
		0xd8, 0xad, 0x29, 0xf7, 0x2e, 0x02, 0x20, 0x19, 0x9b, 0x20, 0xf2, 0x77,
		0xe2, 0x8a, 0x93, 0x94, 0xee, 0x4b, 0x37, 0xe3, 0x94, 0x20, 0x02, 0x1f,
		0xf4, 0x21, 0x2b, 0xb6, 0xf9, 0xbf, 0x4f, 0x60, 0x4b, 0x11, 0x08, 0xcd,
	}

	// baseMultiples has [2^i] * G at position i.
	baseMultiples [384]affinePoint

	initonce sync.Once
)

// Curve represents a short-form Weierstrass curve with a=-3.
type Curve int

// Params returns the parameters for the curve.
func (c Curve) Params() *ecc.CurveParams { return ecc.P384().Params() }

// IsOnCurve reports whether the given (x,y) lies on the curve.
func (c Curve) IsOnCurve(X, Y *big.Int) bool {
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
	fp384Add(x3, x3, &bMon)

	return *y2 == *x3
}

// Add returns the sum of (x1,y1) and (x2,y2)
func (c Curve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	P := newAffinePoint(x1, y1).toJacobian()
	P.mixadd(P, newAffinePoint(x2, y2))
	return P.toAffine().toInt()
}

// Double returns 2*(x,y)
func (c Curve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	P := newAffinePoint(x1, y1).toJacobian()
	P.double()
	return P.toAffine().toInt()
}

// reduceScalar shorten a scalar modulo the order of the curve.
func (c Curve) reduceScalar(k []byte) []byte {
	max := sizeFp >> 3
	if len(k) > max {
		bigK := new(big.Int).SetBytes(k)
		bigK.Mod(bigK, c.Params().N)
		k = bigK.Bytes()
	}
	return k
}

// ScalarMult returns (Qx,Qy)=k*(Px,Py) where k is a number in big-endian form.
func (c Curve) ScalarMult(Px, Py *big.Int, k []byte) (Qx, Qy *big.Int) {
	k = c.reduceScalar(k)
	pt := newAffinePoint(Px, Py)
	sum := &jacobianPoint{}

	for _, ki := range k {
		for b := 7; b >= 0; b-- {
			sum.double()

			if (ki>>uint(b))&1 == 1 {
				sum.mixadd(sum, pt)
			}
		}
	}
	return sum.toAffine().toInt()
}

// ScalarBaseMult returns k*G, where G is the base point of the group
// and k is an integer in big-endian form.
func (c Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	k = c.reduceScalar(k)
	sum := &jacobianPoint{}
	j := 0
	for i := len(k) - 1; i >= 0; i-- {
		for b := 7; b >= 0; b-- {
			if (k[i]>>uint(b))&1 == 1 {
				sum.mixadd(sum, &baseMultiples[j+b])
			}
		}
		j += 8
	}
	return sum.toAffine().toInt()
}

// SimultaneousMult calculates P=mG+nQ, where G is the generator and Q=(x,y,z).
// The scalars m and n are integers in big-endian form. Non-constant time.
func (c Curve) SimultaneousMult(Qx, Qy *big.Int, m, n []byte) (Px, Py *big.Int) {
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
	var P, jR jacobianPoint
	var aR affinePoint
	for i := len(nafN) - 1; i >= 0; i-- {
		P.double()
		// Generator point
		if nafM[i] != 0 {
			idxM := math.Absolute(nafM[i]) >> 1
			aR = baseOddMultiples[idxM]
			if nafM[i] < 0 {
				aR.neg()
			}
			P.mixadd(&P, &aR)
		}
		// Input point
		if nafN[i] != 0 {
			idxN := math.Absolute(nafN[i]) >> 1
			jR = TabQ[idxN]
			if nafN[i] < 0 {
				jR.neg()
			}
			P.add(&P, &jR)
		}
	}
	return P.toAffine().toInt()
}

func initP384() {
	var c Curve
	params := c.Params()
	G := newAffinePoint(params.Gx, params.Gy)
	baseMultiples[0] = *G

	P := G.toJacobian()
	for i := 1; i < len(baseMultiples); i++ {
		P.double()
		baseMultiples[i] = *P.toAffine()
	}
}

func init() { initonce.Do(initP384) }
