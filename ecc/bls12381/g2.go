package bls12381

import (
	"crypto"
	"crypto/subtle"
	"fmt"

	"github.com/cloudflare/circl/ecc/bls12381/ff"
	"github.com/cloudflare/circl/expander"
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
	_z := bls12381.minusZ[:]
	Q := *g
	Q.psi()                   // Q = \psi(g)
	Q.scalarMultShort(_z, &Q) // Q = -[z]\psi(g)
	Q.Add(&Q, g)              // Q = -[z]\psi(g)+g
	Q.psi()                   // Q = -[z]\psi^2(g)+\psi(g)
	Q.psi()                   // Q = -[z]\psi^3(g)+\psi^2(g)

	return Q.IsEqual(g) // Equivalent to verification equation in paper
}

// psi is the Galbraith-Scott endomorphism. See https://eprint.iacr.org/2008/117.
func (g *G2) psi() {
	g.x.Frob(&g.x)
	g.y.Frob(&g.y)
	g.z.Frob(&g.z)
	g.x.Mul(&g2Psi.alpha, &g.x)
	g.y.Mul(&g2Psi.beta, &g.y)
}

// clearCofactor maps g to a point in the r-torsion subgroup.
//
// This method multiplies g times a multiple of the cofactor as proposed by
// Fuentes-Knapp-Rodríguez at https://doi.org/10.1007/978-3-642-28496-0_25.
//
// The explicit formulas for BLS curves are in Section 4.1 of Budroni-Pintore
// "Efficient hash maps to G2 on BLS curves" at https://eprint.iacr.org/2017/419
//
//	h(a)P = [x^2-x-1]P + [x-1]ψ(P) + ψ^2(2P)
func (g *G2) clearCofactor() {
	x := bls12381.minusZ[:]
	xP, psiP := &G2{}, &G2{}
	_2P := *g

	_2P.Double()              // 2P
	_2P.psi()                 // ψ(2P)
	_2P.psi()                 // ψ^2(2P)
	xP.scalarMultShort(x, g)  // -xP
	xP.Add(xP, g)             // -xP + P = [-x+1]P
	*psiP = *xP               //
	psiP.psi()                // ψ(-xP + P) = [-x+1]ψ(P)
	xP.scalarMultShort(x, xP) // x^2P - xP = [x^2-x]P
	g.Add(g, psiP)            // P + [-x+1]ψ(P)
	g.Neg()                   // -P + [x-1]ψ(P)
	g.Add(g, xP)              // [x^2-x-1]P + [x-1]ψ(P)
	g.Add(g, &_2P)            // [x^2-x-1]P + [x-1]ψ(P) + 2ψ^2(P)
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

// scalarMultShort multiplies by a short, constant scalar k, where k is the
// scalar in big-endian order. Runtime depends on the scalar.
func (g *G2) scalarMultShort(k []byte, P *G2) {
	// Since the scalar is short and low Hamming weight not much helps.
	var Q G2
	Q.SetIdentity()
	N := 8 * len(k)
	for i := 0; i < N; i++ {
		Q.Double()
		bit := 0x1 & (k[i/8] >> uint(7-i%8))
		if bit != 0 {
			Q.Add(&Q, P)
		}
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

// EncodeToCurve is a non-uniform encoding from an input byte string (and
// an optional domain separation tag) to elements in G2. This function must not
// be used as a hash function, otherwise use G2.Hash instead.
func (g *G2) Encode(input, dst []byte) {
	const L = 64
	pseudo := expander.NewExpanderMD(crypto.SHA256, dst).Expand(input, 2*L)

	var u ff.Fp2
	u[0].SetBytes(pseudo[0*L : 1*L])
	u[1].SetBytes(pseudo[1*L : 2*L])

	var q isogG2Point
	q.sswu(&u)
	g.evalIsogG2(&q)
	g.clearCofactor()
}

// Hash produces an element of G2 from the hash of an input byte string and
// an optional domain separation tag. This function is safe to use when a
// random oracle returning points in G2 be required.
func (g *G2) Hash(input, dst []byte) {
	const L = 64
	pseudo := expander.NewExpanderMD(crypto.SHA256, dst).Expand(input, 4*L)

	var u0, u1 ff.Fp2
	u0[0].SetBytes(pseudo[0*L : 1*L])
	u0[1].SetBytes(pseudo[1*L : 2*L])
	u1[0].SetBytes(pseudo[2*L : 3*L])
	u1[1].SetBytes(pseudo[3*L : 4*L])

	var q0, q1 isogG2Point
	q0.sswu(&u0)
	q1.sswu(&u1)
	var p0, p1 G2
	p0.evalIsogG2(&q0)
	p1.evalIsogG2(&q1)
	g.Add(&p0, &p1)
	g.clearCofactor()
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
