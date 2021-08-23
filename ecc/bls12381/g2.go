package bls12381

import (
	"crypto/subtle"
	"fmt"

	"github.com/cloudflare/circl/ecc/bls12381/ff"
)

// G2Size is the length in bytes of an element in G2.
const G2Size = 2 * ff.Fp2Size

// G2 is a point in the twist of the BLS12 curve over Fp2.
type G2 struct{ x, y, z ff.Fp2 }

func (g G2) String() string { return fmt.Sprintf("x: %v\ny: %v\nz: %v", g.x, g.y, g.z) }

// Bytes serializes a G2 element.
func (g *G2) Bytes() []byte { g.Normalize(); return append(g.x.Bytes(), g.y.Bytes()...) }

// Set is (TMP).
func (g *G2) Set(P *G2) { g.x.Set(&P.x); g.y.Set(&P.y); g.z.Set(&P.z) }

// SetBytes deserializes g, and returns an error if not in the group
func (g *G2) SetBytes(b []byte) error {
	if len(b) < G2Size {
		return fmt.Errorf("incorrect length")
	}
	err := g.x.SetBytes(b[:ff.Fp2Size])
	if err != nil {
		return err
	}
	err = g.y.SetBytes(b[ff.Fp2Size:])
	if err != nil {
		return err
	}
	g.z.SetOne()
	if !g.IsOnG2() {
		return fmt.Errorf("result not in group")
	}
	return nil
}

// Neg inverts g.
func (g *G2) Neg() { g.y.Neg() }

// SetIdentity assigns g to the identity element.
func (g *G2) SetIdentity() { g.x = ff.Fp2{}; g.y.SetOne(); g.z = ff.Fp2{} }

// IsOnG2 returns true if the point is in the group G2.
func (g *G2) IsOnG2() bool { return g.IsOnCurve() && g.IsRTorsion() }

// IsIdentity return true if the point is the identity of G2.
func (g *G2) IsIdentity() bool { return g.z.IsZero() == 1 }

// cmove sets g to P if b == 1
func (g *G2) cmov(P *G2, b int) {
	(&g.x).CMov(&g.x, &P.x, b)
	(&g.y).CMov(&g.y, &P.y, b)
	(&g.z).CMov(&g.z, &P.z, b)
}

// IsRTorsion returns true if point is r-torsion.
func (g *G2) IsRTorsion() bool { var P G2; P.scalarMult(ff.ScalarOrder(), g); return P.IsIdentity() }

// Double updates g = 2g.
func (g *G2) Double() { doubleAndLine(g, nil) }

// Add updates g=P+Q.
func (g *G2) Add(P, Q *G2) { addAndLine(g, P, Q, nil) }

// ScalarMult calculates g = kP.
func (g *G2) ScalarMult(k *Scalar, P *G2) { g.scalarMult(k.Bytes(), P) }

func (g *G2) scalarMult(k []byte, P *G2) {
	var Q G2
	Q.SetIdentity()
	T := &G2{}
	var mults [16]G2
	mults[0].SetIdentity()
	mults[1].Set(P)
	for i := 1; i < 8; i++ {
		mults[2*i].Set(&mults[i])
		mults[2*i].Double()
		mults[2*i+1].Add(&mults[2*i], P)
	}
	for i := 8*len(k) - 4; i >= 0; i -= 4 {
		Q.Double()
		Q.Double()
		Q.Double()
		Q.Double()
		idx := 0xf & (k[i/8] >> uint(i%8))
		for j := 0; j < 16; j++ {
			T.cmov(&mults[j], subtle.ConstantTimeByteEq(idx, uint8(j)))
		}
		Q.Add(&Q, T)
	}
	g.Set(&Q)
}

// IsEqual returns true if g and p are equivalent.
func (g *G2) IsEqual(p *G2) bool {
	var lx, rx, ly, ry ff.Fp2
	lx.Mul(&g.x, &p.z) // lx = x1*z2
	rx.Mul(&p.x, &g.z) // rx = x2*z1
	lx.Sub(&lx, &rx)   // lx = lx-rx
	ly.Mul(&g.y, &p.z) // ly = y1*z2
	ry.Mul(&p.y, &g.z) // ry = y2*z1
	ly.Sub(&ly, &ry)   // ly = ly-ry
	return lx.IsZero() == 1 && ly.IsZero() == 1
}

// IsOnCurve returns true if g is a valid point on the curve.
func (g *G2) IsOnCurve() bool {
	var x3, z3, y2 ff.Fp2
	y2.Sqr(&g.y)             // y2 = y^2
	y2.Mul(&y2, &g.z)        // y2 = y^2*z
	x3.Sqr(&g.x)             // x3 = x^2
	x3.Mul(&x3, &g.x)        // x3 = x^3
	z3.Sqr(&g.z)             // z3 = z^2
	z3.Mul(&z3, &g.z)        // z3 = z^3
	z3.Mul(&z3, &g2Params.b) // z3 = (4+4i)*z^3
	x3.Add(&x3, &z3)         // x3 = x^3 + (4+4i)*z^3
	y2.Sub(&y2, &x3)         // y2 = y^2*z - (x^3 + (4+4i)*z^3)
	return y2.IsZero() == 1
}

// Normalize updates g with its affine representation.
func (g *G2) Normalize() {
	if g.z.IsZero() != 1 {
		var invZ ff.Fp2
		invZ.Inv(&g.z)
		g.x.Mul(&g.x, &invZ)
		g.y.Mul(&g.y, &invZ)
		g.z.Mul(&g.z, &invZ)
	}
}

// G2Generator returns the generator point of G2.
func G2Generator() *G2 {
	var G G2
	G.x.Set(&g2Params.genX)
	G.y.Set(&g2Params.genY)
	G.z.SetOne()
	return &G
}
