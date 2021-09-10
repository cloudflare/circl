package bls12381

import (
	"crypto/subtle"
	"fmt"

	"github.com/cloudflare/circl/ecc/bls12381/ff"
)

// G2Size is the length in bytes of an element in G2 in uncompressed form..
const G2Size = 2 * ff.Fp2Size

// G2SizeCompressed is the length in bytes of an element in G2 in compressed form.
const G2SizeCompressed = ff.Fp2Size

// G2 is a point in the twist of the BLS12 curve over Fp2.
type G2 struct{ x, y, z ff.Fp2 }

func (g G2) String() string { return fmt.Sprintf("x: %v\ny: %v\nz: %v", g.x, g.y, g.z) }

// Bytes serializes a G2 element in uncompressed form.
func (g G2) Bytes() []byte { return g.encodeBytes(false) }

// Bytes serializes a G2 element in compressed form.
func (g G2) BytesCompressed() []byte { return g.encodeBytes(true) }

// SetBytes sets g to the value in bytes, and returns a non-nil error if not in G2.
func (g *G2) SetBytes(b []byte) error {
	if len(b) < G2SizeCompressed {
		return errInputLength
	}

	isCompressed := int((b[0] >> 7) & 0x1)
	isInfinity := int((b[0] >> 6) & 0x1)
	isBigYCoord := int((b[0] >> 5) & 0x1)

	if isInfinity == 1 {
		l := G2Size
		if isCompressed == 1 {
			l = G2SizeCompressed
		}
		zeros := make([]byte, l-1)
		if (b[0]&0x1F) != 0 || subtle.ConstantTimeCompare(b[1:], zeros) != 1 {
			return errEncoding
		}
		g.SetIdentity()
		return nil
	}

	x := (&[ff.Fp2Size]byte{})[:]
	copy(x, b)
	x[0] &= 0x1F
	if err := g.x.UnmarshalBinary(x); err != nil {
		return err
	}

	if isCompressed == 1 {
		x3b := &ff.Fp2{}
		x3b.Sqr(&g.x)
		x3b.Mul(x3b, &g.x)
		x3b.Add(x3b, &g2Params.b)
		if g.y.Sqrt(x3b) == 0 {
			return errEncoding
		}
		if g.y.IsNegative() != isBigYCoord {
			g.y.Neg()
		}
	} else {
		if len(b) < G2Size {
			return errInputLength
		}
		if err := g.y.UnmarshalBinary(b[ff.Fp2Size:G2Size]); err != nil {
			return err
		}
	}

	g.z.SetOne()
	if !g.IsOnG2() {
		return errEncoding
	}
	return nil
}

func (g G2) encodeBytes(compressed bool) []byte {
	g.toAffine()
	var isCompressed, isInfinity, isBigYCoord byte
	if compressed {
		isCompressed = 1
	}
	if g.z.IsZero() == 1 {
		isInfinity = 1
	}
	if isCompressed == 1 && isInfinity == 0 {
		isBigYCoord = byte(g.y.IsNegative())
	}

	bytes, _ := g.x.MarshalBinary()
	if isCompressed == 0 {
		yBytes, _ := g.y.MarshalBinary()
		bytes = append(bytes, yBytes...)
	}
	if isInfinity == 1 {
		l := len(bytes)
		for i := 0; i < l; i++ {
			bytes[i] = 0
		}
	}

	bytes[0] = bytes[0]&0x1F | headerEncoding(isCompressed, isInfinity, isBigYCoord)

	return bytes
}

// Neg inverts g.
func (g *G2) Neg() { g.y.Neg() }

// SetIdentity assigns g to the identity element.
func (g *G2) SetIdentity() { g.x = ff.Fp2{}; g.y.SetOne(); g.z = ff.Fp2{} }

// isValidProjective returns true if the point is not a projective point.
func (g *G2) isValidProjective() bool { return (g.x.IsZero() & g.y.IsZero() & g.z.IsZero()) != 1 }

// IsOnG2 returns true if the point is in the group G2.
func (g *G2) IsOnG2() bool { return g.isValidProjective() && g.isOnCurve() && g.isRTorsion() }

// IsIdentity return true if the point is the identity of G2.
func (g *G2) IsIdentity() bool { return g.isValidProjective() && (g.z.IsZero() == 1) }

// cmov sets g to P if b == 1
func (g *G2) cmov(P *G2, b int) {
	(&g.x).CMov(&g.x, &P.x, b)
	(&g.y).CMov(&g.y, &P.y, b)
	(&g.z).CMov(&g.z, &P.z, b)
}

// isRTorsion returns true if point is in the r-torsion subgroup.
func (g *G2) isRTorsion() bool {
	// Bowe, "Faster Subgroup Checks for BLS12-381" (https://eprint.iacr.org/2019/814)
	Q := *g
	Q.psi()                                // Q = \psi(g)
	Q.scalarMult(g2PsiCoeff.minusZ[:], &Q) // Q = -[z]\psi(g)
	Q.Add(&Q, g)                           // Q = -[z]\psi(g)+g
	Q.psi()                                // Q = -[z]\psi^2(g)+\psi(g)
	Q.psi()                                // Q = -[z]\psi^3(g)+\psi^2(g)

	return Q.IsEqual(g) // Equivalent to verification equation in paper
}

func (g *G2) psi() {
	g.x.Frob(&g.x)
	g.y.Frob(&g.y)
	g.z.Frob(&g.z)
	g.x.Mul(&g2PsiCoeff.alpha, &g.x)
	g.y.Mul(&g2PsiCoeff.beta, &g.y)
}

// Double updates g = 2g.
func (g *G2) Double() { doubleAndLine(g, nil) }

// Add updates g=P+Q.
func (g *G2) Add(P, Q *G2) { addAndLine(g, P, Q, nil) }

// ScalarMult calculates g = kP.
func (g *G2) ScalarMult(k *Scalar, P *G2) { b, _ := k.MarshalBinary(); g.scalarMult(b, P) }

// scalarMult calculates g = kP, where k is the scalar in big-endian order.
func (g *G2) scalarMult(k []byte, P *G2) {
	var Q G2
	Q.SetIdentity()
	T := &G2{}
	var mults [16]G2
	mults[0].SetIdentity()
	mults[1] = *P
	for i := 1; i < 8; i++ {
		mults[2*i] = mults[i]
		mults[2*i].Double()
		mults[2*i+1].Add(&mults[2*i], P)
	}
	N := 8 * len(k)
	for i := 0; i < N; i += 4 {
		Q.Double()
		Q.Double()
		Q.Double()
		Q.Double()
		idx := 0xf & (k[i/8] >> uint(4-i%8))
		for j := 0; j < 16; j++ {
			T.cmov(&mults[j], subtle.ConstantTimeByteEq(idx, uint8(j)))
		}
		Q.Add(&Q, T)
	}
	*g = Q
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

// isOnCurve returns true if g is a valid point on the curve.
func (g *G2) isOnCurve() bool {
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

// toAffine updates g with its affine representation.
func (g *G2) toAffine() {
	if g.z.IsZero() != 1 {
		var invZ ff.Fp2
		invZ.Inv(&g.z)
		g.x.Mul(&g.x, &invZ)
		g.y.Mul(&g.y, &invZ)
		g.z.SetOne()
	}
}

// G2Generator returns the generator point of G2.
func G2Generator() *G2 {
	var G G2
	G.x = g2Params.genX
	G.y = g2Params.genY
	G.z.SetOne()
	return &G
}
