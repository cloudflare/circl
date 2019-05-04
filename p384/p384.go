// Package p384 is an optimized P-384 implementation.
package p384

import (
	"crypto/elliptic"
	"math/big"
	"sync"
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

type Curve struct{}

func (c *Curve) Params() *elliptic.CurveParams {
	return elliptic.P384().Params()
}

func (c *Curve) IsOnCurve(X, Y *big.Int) bool {
	x := fp384Set(X)
	y := fp384Set(Y)
	montEncode(x, x)
	montEncode(y, y)

	y2, x3 := &fp384{}, &fp384{}
	fp384Mul(y2, y, y)
	fp384Mul(x3, x, x)
	fp384Mul(x3, x3, x)

	threeX := &fp384{}
	fp384Add(threeX, x, x)
	fp384Add(threeX, threeX, x)

	fp384Sub(x3, x3, threeX)
	fp384Add(x3, x3, &bMon)

	return *y2 == *x3
}

func (c *Curve) add(a *jacobianPoint, b *affinePoint) *jacobianPoint {
	if a.IsZero() {
		return b.ToJacobian()
	} else if b.IsZero() {
		return a.Dup()
	}

	z1z1, u2 := &fp384{}, &fp384{}
	fp384Mul(z1z1, &a.z, &a.z)
	fp384Mul(u2, &b.x, z1z1)

	s2 := &fp384{}
	fp384Mul(s2, &b.y, &a.z)
	fp384Mul(s2, s2, z1z1)
	if a.x == *u2 {
		if a.y != *s2 {
			return &jacobianPoint{}
		}
		return c.double(a)
	}

	h, r := &fp384{}, &fp384{}
	fp384Sub(h, u2, &a.x)
	fp384Sub(r, s2, &a.y)

	h2, h3 := &fp384{}, &fp384{}
	fp384Mul(h2, h, h)
	fp384Mul(h3, h2, h)

	h2x1 := &fp384{}
	fp384Mul(h2x1, h2, &a.x)

	x3, y3, z3 := &fp384{}, &fp384{}, &fp384{}
	fp384Mul(x3, r, r)
	fp384Sub(x3, x3, h3)
	fp384Sub(x3, x3, h2x1)
	fp384Sub(x3, x3, h2x1)

	fp384Sub(y3, h2x1, x3)
	fp384Mul(y3, y3, r)
	h3y1 := &fp384{}
	fp384Mul(h3y1, h3, &a.y)
	fp384Sub(y3, y3, h3y1)

	fp384Mul(z3, h, &a.z)

	return &jacobianPoint{*x3, *y3, *z3}
}

func (c *Curve) double(a *jacobianPoint) *jacobianPoint {
	delta, gamma, alpha, alpha2 := &fp384{}, &fp384{}, &fp384{}, &fp384{}
	fp384Mul(delta, &a.z, &a.z)
	fp384Mul(gamma, &a.y, &a.y)
	fp384Sub(alpha, &a.x, delta)
	fp384Add(alpha2, &a.x, delta)
	fp384Mul(alpha, alpha, alpha2)
	*alpha2 = *alpha
	fp384Add(alpha, alpha, alpha)
	fp384Add(alpha, alpha, alpha2)

	beta := &fp384{}
	fp384Mul(beta, &a.x, gamma)

	x3, beta8 := &fp384{}, &fp384{}
	fp384Mul(x3, alpha, alpha)
	fp384Add(beta8, beta, beta)
	fp384Add(beta8, beta8, beta8)
	fp384Add(beta8, beta8, beta8)
	fp384Sub(x3, x3, beta8)

	z3 := &fp384{}
	fp384Add(z3, &a.y, &a.z)
	fp384Mul(z3, z3, z3)
	fp384Sub(z3, z3, gamma)
	fp384Sub(z3, z3, delta)

	fp384Add(beta, beta, beta)
	fp384Add(beta, beta, beta)
	fp384Sub(beta, beta, x3)

	y3 := &fp384{}
	fp384Mul(y3, alpha, beta)

	fp384Mul(gamma, gamma, gamma)
	fp384Add(gamma, gamma, gamma)
	fp384Add(gamma, gamma, gamma)
	fp384Add(gamma, gamma, gamma)
	fp384Sub(y3, y3, gamma)

	return &jacobianPoint{*x3, *y3, *z3}
}

// Add returns the sum of (x1,y1) and (x2,y2)
func (c *Curve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	pt := c.add(newAffinePoint(x1, y1).ToJacobian(), newAffinePoint(x2, y2))
	return pt.ToAffine().ToInt()
}

// Double returns 2*(x,y)
func (c *Curve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	pt := c.double(newAffinePoint(x1, y1).ToJacobian())
	return pt.ToAffine().ToInt()
}

// ScalarMult returns k*(Bx,By) where k is a number in big-endian form.
func (c *Curve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	pt := newAffinePoint(x1, y1)
	sum := &jacobianPoint{}

	for i := 0; i < len(k); i++ {
		for j := 7; j >= 0; j-- {
			sum = c.double(sum)

			if (k[i]>>uint(j))&1 == 1 {
				sum = c.add(sum, pt)
			}
		}
	}

	return sum.ToAffine().ToInt()
}

// ScalarBaseMult returns k*G, where G is the base point of the group
// and k is an integer in big-endian form.
func (c *Curve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	sum := &jacobianPoint{}
	max := sizeFp
	if len(k) < sizeFp {
		max = len(k)
	}

	for i := 0; i < max; i++ {
		for j := 7; j >= 0; j-- {
			if (k[i]>>uint(j))&1 == 1 {
				sum = c.add(sum, &baseMultiples[8*(max-i-1)+j])
			}
		}
	}
	for i := sizeFp; i < len(k); i++ {
		for j := 7; j >= 0; j-- {
			sum = c.double(sum)

			if (k[i]>>uint(j))&1 == 1 {
				sum = c.add(sum, &baseMultiples[0])
			}
		}
	}

	return sum.ToAffine().ToInt()
}

func (c *Curve) CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int) {
	ptA := baseMultiples[0]
	ptB := newAffinePoint(bigX, bigY)
	ptC := c.add(ptA.ToJacobian(), ptB).ToAffine()
	sum := &jacobianPoint{}

	kb, ks := 0, 0
	if len(baseScalar) < len(scalar) {
		kb = len(scalar) - len(baseScalar)
	} else if len(scalar) < len(baseScalar) {
		ks = len(baseScalar) - len(scalar)
	}

	for i := 0; i < len(baseScalar)+kb; i++ {
		for j := 7; j >= 0; j-- {
			sum = c.double(sum)

			var a, b byte
			if k := i - kb; k >= 0 && k < len(baseScalar) {
				a = (baseScalar[k] >> uint(j)) & 1
			}
			if k := i - ks; k >= 0 && k < len(scalar) {
				b = (scalar[k] >> uint(j)) & 1
			}

			if a == 1 && b == 0 {
				sum = c.add(sum, &ptA)
			} else if a == 0 && b == 1 {
				sum = c.add(sum, ptB)
			} else if a == 1 && b == 1 {
				sum = c.add(sum, ptC)
			}
		}
	}

	return sum.ToAffine().ToInt()
}

func initP384() {
	params := elliptic.P384().Params()
	baseMultiples[0] = *newAffinePoint(params.Gx, params.Gy)

	c := &Curve{}
	for i := 1; i < len(baseMultiples); i++ {
		pt := c.double(baseMultiples[i-1].ToJacobian()).ToAffine()
		baseMultiples[i] = *pt
	}
}

func init() {
	initonce.Do(initP384)
}
