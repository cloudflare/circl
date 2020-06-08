package bls12381

import (
	"fmt"

	"github.com/cloudflare/circl/ecc/bls12381/ff"
)

// G2 is a point in the twist of the BLS12 curve over Fp2.
type G2 struct {
	x ff.Fp2
	y ff.Fp2
	z ff.Fp2
}

func (g G2) String() string { return fmt.Sprintf("x: %v\ny: %v\nz: %v", g.x, g.y, g.z) }

// Set is (TMP)
func (g *G2) Set(P *G2) {
	g.x.Set(&P.x)
	g.y.Set(&P.y)
	g.z.Set(&P.z)
}

// Neg is
func (g *G2) Neg() { g.y.Neg() }

// SetIdentity is
func (g *G2) SetIdentity() { g.x.SetZero(); g.y.SetOne(); g.z.SetZero() }

// IsOnG2 returns true if the point is in the group G2.
func (g *G2) IsOnG2() bool { return g.IsOnCurve() && g.IsRTorsion() }

// IsIdentity return true if the point is the identity of G2.
func (g *G2) IsIdentity() bool { return g.z.IsZero() }

// IsRTorsion returns true if point is r-torsion.
func (g *G2) IsRTorsion() bool { var P G2; P.ScalarMult(&primeOrder, g); return P.IsIdentity() }

// Double is
func (g *G2) Double() { doubleAndLine(g, nil) }

// Add is
func (g *G2) Add(P, Q *G2) { addAndLine(g, P, Q, nil) }

// ScalarMult is
func (g *G2) ScalarMult(k *Scalar, P *G2) {
	var Q G2
	Q.SetIdentity()
	for i := 8*ScalarSize - 1; i >= 0; i-- {
		Q.Double()
		bit := 0x1 & (k[i/8] >> uint(i%8))
		if bit != 0 {
			Q.Add(&Q, P)
		}
	}
	g.Set(&Q)
}

// IsEqual is
func (g *G2) IsEqual(p *G2) bool {
	var lx, rx, ly, ry ff.Fp2
	lx.Mul(&g.x, &p.z) // lx = x1*z2
	rx.Mul(&p.x, &g.z) // rx = x2*z1
	lx.Sub(&lx, &rx)   // lx = lx-rx
	ly.Mul(&g.y, &p.z) // ly = y1*z2
	ry.Mul(&p.y, &g.z) // ry = y2*z1
	ly.Sub(&ly, &ry)   // ly = ly-ry
	return lx.IsZero() && ly.IsZero()
}

// IsOnCurve is
func (g *G2) IsOnCurve() bool {
	var x3, z3, y2 ff.Fp2
	y2.Sqr(&g.y)           // y2 = y^2
	y2.Mul(&y2, &g.z)      // y2 = y^2*z
	x3.Sqr(&g.x)           // x3 = x^2
	x3.Mul(&x3, &g.x)      // x3 = x^3
	z3.Sqr(&g.z)           // z3 = z^2
	z3.Mul(&z3, &g.z)      // z3 = z^3
	z3.Mul(&z3, &g2ParamB) // z3 = (4+4i)*z^3
	x3.Add(&x3, &z3)       // x3 = x^3 + (4+4i)*z^3
	y2.Sub(&y2, &x3)       // y2 = y^2*z - (x^3 + (4+4i)*z^3)
	return y2.IsZero()
}

// ToAffine is
func (g *G2) ToAffine() {
	var invZ ff.Fp2
	invZ.Inv(&g.z)
	g.x.Mul(&g.x, &invZ)
	g.y.Mul(&g.y, &invZ)
	g.z.Mul(&g.z, &invZ)
}

// G2Generator returns the generator point of G2.
func G2Generator() *G2 {
	var G G2
	G.x.Set(&g2GenX)
	G.y.Set(&g2GenY)
	G.z.SetOne()
	return &G
}
