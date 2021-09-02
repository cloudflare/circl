package bls12381

import (
	"crypto"
	"crypto/subtle"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/ecc/bls12381/ff"
	"github.com/cloudflare/circl/group"
)

// G1Size is the length in bytes of an element in G1.
const G1Size = 2 * ff.FpSize

// G1 is a point in the BLS12 curve over Fp.
type G1 struct{ x, y, z ff.Fp }

func (g G1) String() string { return fmt.Sprintf("x: %v\ny: %v\nz: %v", g.x, g.y, g.z) }

// Bytes serializes a G1 element.
func (g *G1) Bytes() []byte { g.toAffine(); return append(g.x.Bytes(), g.y.Bytes()...) }

// Set is (TMP).
func (g *G1) Set(P *G1) { g.x.Set(&P.x); g.y.Set(&P.y); g.z.Set(&P.z) }

// SetBytes sets g to the value in bytes, and returns a non-nil error if not in G1.
func (g *G1) SetBytes(b []byte) error {
	if len(b) < G1Size {
		return fmt.Errorf("incorrect length")
	}
	err := g.x.SetBytes(b[:ff.FpSize])
	if err != nil {
		return err
	}
	err = g.y.SetBytes(b[ff.FpSize:])
	if err != nil {
		return err
	}
	g.z.SetOne()
	if !g.IsOnG1() {
		return fmt.Errorf("point not in G1")
	}
	return nil
}

// Neg inverts g.
func (g *G1) Neg() { g.y.Neg() }

// SetIdentity assigns g to the identity element.
func (g *G1) SetIdentity() { g.x = ff.Fp{}; g.y.SetOne(); g.z = ff.Fp{} }

// isValidProjective returns true if the point is not a projective point.
func (g *G1) isValidProjective() bool { return (g.x.IsZero() & g.y.IsZero() & g.z.IsZero()) != 1 }

// IsOnG1 returns true if the point is in the group G1.
func (g *G1) IsOnG1() bool { return g.isValidProjective() && g.isOnCurve() && g.isRTorsion() }

// IsIdentity return true if the point is the identity of G1.
func (g *G1) IsIdentity() bool { return g.isValidProjective() && (g.z.IsZero() == 1) }

// cmov sets g to P if b == 1
func (g *G1) cmov(P *G1, b int) {
	(&g.x).CMov(&g.x, &P.x, b)
	(&g.y).CMov(&g.y, &P.y, b)
	(&g.z).CMov(&g.z, &P.z, b)
}

// isRTorsion returns true if point is in the r-torsion subgroup.
func (g *G1) isRTorsion() bool {
	// Bowe, "Faster Subgroup Checks for BLS12-381" (https://eprint.iacr.org/2019/814)
	Q, _2sP, ssP := &G1{}, *g, *g

	_2sP.x.Mul(&g.x, &g1Check.beta0)      // s(P)
	_2sP.Double()                         // 2*s(P)
	ssP.x.Mul(&g.x, &g1Check.beta1)       // s(s(P))
	Q.Add(g, &ssP)                        // P + s(s(P))
	Q.Neg()                               // -P - s(s(P))
	Q.Add(Q, &_2sP)                       // 2*s(P) - P - s(s(P))
	Q.scalarMultShort(g1Check.coef[:], Q) // coef * [2*s(P) - P - s(s(P))]
	ssP.Neg()                             // -s(s(P))
	Q.Add(Q, &ssP)                        // coef * [2*s(P) - P - s(s(P))] - s(s(P))

	return Q.IsIdentity()
}

// clearCofactor maps g to a point in the r-torsion subgroup.
//
// This method multiplies g times (1-z) rather than (z-1)^2/3, where z is the
// BLS12 parameter. This is enough to remove points of order
//  h \in {3, 11, 10177, 859267, 52437899},
// and because there are no points of order h^2. See Section 5 of Wahby-Boneh
// "Fast and simple constant-time hashing to the BLS12-381 elliptic curve" at
// https://eprint.iacr.org/2019/403
func (g *G1) clearCofactor() { g.scalarMultShort(g1Params.cofactorSmall[:], g) }

// Double updates g = 2g.
func (g *G1) Double() {
	// Reference:
	//   "Complete addition formulas for prime order elliptic curves" by
	//   Costello-Renes-Batina. [Alg.9] (eprint.iacr.org/2015/1060).
	var R G1
	X, Y, Z := &g.x, &g.y, &g.z
	X3, Y3, Z3 := &R.x, &R.y, &R.z
	var f0, f1, f2 ff.Fp
	t0, t1, t2 := &f0, &f1, &f2
	_3B := &g1Params._3b
	t0.Sqr(Y)       // 1.  t0 =  Y * Y
	Z3.Add(t0, t0)  // 2.  Z3 = t0 + t0
	Z3.Add(Z3, Z3)  // 3.  Z3 = Z3 + Z3
	Z3.Add(Z3, Z3)  // 4.  Z3 = Z3 + Z3
	t1.Mul(Y, Z)    // 5.  t1 =  Y * Z
	t2.Sqr(Z)       // 6.  t2 =  Z * Z
	t2.Mul(_3B, t2) // 7.  t2 = b3 * t2
	X3.Mul(t2, Z3)  // 8.  X3 = t2 * Z3
	Y3.Add(t0, t2)  // 9.  Y3 = t0 + t2
	Z3.Mul(t1, Z3)  // 10. Z3 = t1 * Z3
	t1.Add(t2, t2)  // 11. t1 = t2 + t2
	t2.Add(t1, t2)  // 12. t2 = t1 + t2
	t0.Sub(t0, t2)  // 13. t0 = t0 - t2
	Y3.Mul(t0, Y3)  // 14. Y3 = t0 * Y3
	Y3.Add(X3, Y3)  // 15. Y3 = X3 + Y3
	t1.Mul(X, Y)    // 16. t1 =  X * Y
	X3.Mul(t0, t1)  // 17. X3 = t0 * t1
	X3.Add(X3, X3)  // 18. X3 = X3 + X3
	g.Set(&R)
}

// Add updates g=P+Q.
func (g *G1) Add(P, Q *G1) {
	// Reference:
	//   "Complete addition formulas for prime order elliptic curves" by
	//   Costello-Renes-Batina. [Alg.7] (eprint.iacr.org/2015/1060).
	var R G1
	X1, Y1, Z1 := &P.x, &P.y, &P.z
	X2, Y2, Z2 := &Q.x, &Q.y, &Q.z
	X3, Y3, Z3 := &R.x, &R.y, &R.z
	_3B := &g1Params._3b
	var f0, f1, f2, f3, f4 ff.Fp
	t0, t1, t2, t3, t4 := &f0, &f1, &f2, &f3, &f4
	t0.Mul(X1, X2)  // 1.  t0 = X1 * X2
	t1.Mul(Y1, Y2)  // 2.  t1 = Y1 * Y2
	t2.Mul(Z1, Z2)  // 3.  t2 = Z1 * Z2
	t3.Add(X1, Y1)  // 4.  t3 = X1 + Y1
	t4.Add(X2, Y2)  // 5.  t4 = X2 + Y2
	t3.Mul(t3, t4)  // 6.  t3 = t3 * t4
	t4.Add(t0, t1)  // 7.  t4 = t0 + t1
	t3.Sub(t3, t4)  // 8.  t3 = t3 - t4
	t4.Add(Y1, Z1)  // 9.  t4 = Y1 + Z1
	X3.Add(Y2, Z2)  // 10. X3 = Y2 + Z2
	t4.Mul(t4, X3)  // 11. t4 = t4 * X3
	X3.Add(t1, t2)  // 12. X3 = t1 + t2
	t4.Sub(t4, X3)  // 13. t4 = t4 - X3
	X3.Add(X1, Z1)  // 14. X3 = X1 + Z1
	Y3.Add(X2, Z2)  // 15. Y3 = X2 + Z2
	X3.Mul(X3, Y3)  // 16. X3 = X3 * Y3
	Y3.Add(t0, t2)  // 17. Y3 = t0 + t2
	Y3.Sub(X3, Y3)  // 18. Y3 = X3 - Y3
	X3.Add(t0, t0)  // 19. X3 = t0 + t0
	t0.Add(X3, t0)  // 20. t0 = X3 + t0
	t2.Mul(_3B, t2) // 21. t2 = b3 * t2
	Z3.Add(t1, t2)  // 22. Z3 = t1 + t2
	t1.Sub(t1, t2)  // 23. t1 = t1 - t2
	Y3.Mul(_3B, Y3) // 24. Y3 = b3 * Y3
	X3.Mul(t4, Y3)  // 25. X3 = t4 * Y3
	t2.Mul(t3, t1)  // 26. t2 = t3 * t1
	X3.Sub(t2, X3)  // 27. X3 = t2 - X3
	Y3.Mul(Y3, t0)  // 28. Y3 = Y3 * t0
	t1.Mul(t1, Z3)  // 29. t1 = t1 * Z3
	Y3.Add(t1, Y3)  // 30. Y3 = t1 + Y3
	t0.Mul(t0, t3)  // 31. t0 = t0 * t3
	Z3.Mul(Z3, t4)  // 32. Z3 = Z3 * t4
	Z3.Add(Z3, t0)  // 33. Z3 = Z3 + t0
	g.Set(&R)
}

// ScalarMult calculates g = kP.
func (g *G1) ScalarMult(k *Scalar, P *G1) { g.scalarMult(k.Bytes(), P) }

// scalarMult calculates g = kP, where k is the scalar in big-endian order.
func (g *G1) scalarMult(k []byte, P *G1) {
	var Q G1
	Q.SetIdentity()
	T := &G1{}
	var mults [16]G1
	mults[0].SetIdentity()
	mults[1].Set(P)
	for i := 1; i < 8; i++ {
		mults[2*i].Set(&mults[i])
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
	g.Set(&Q)
}

// scalarMultShort multiplies by a short, constant scalar k, where k is the
// scalar in big-endian order. Runtime depends on the scalar.
func (g *G1) scalarMultShort(k []byte, P *G1) {
	// Since the scalar is short and low Hamming weight not much helps.
	var Q G1
	Q.SetIdentity()
	N := 8 * len(k)
	for i := 0; i < N; i++ {
		Q.Double()
		bit := 0x1 & (k[i/8] >> uint(7-i%8))
		if bit != 0 {
			Q.Add(&Q, P)
		}
	}
	g.Set(&Q)
}

// IsEqual returns true if g and p are equivalent.
func (g *G1) IsEqual(p *G1) bool {
	var lx, rx, ly, ry ff.Fp
	lx.Mul(&g.x, &p.z) // lx = x1*z2
	rx.Mul(&p.x, &g.z) // rx = x2*z1
	lx.Sub(&lx, &rx)   // lx = lx-rx
	ly.Mul(&g.y, &p.z) // ly = y1*z2
	ry.Mul(&p.y, &g.z) // ry = y2*z1
	ly.Sub(&ly, &ry)   // ly = ly-ry
	return g.isValidProjective() && p.isValidProjective() && lx.IsZero() == 1 && ly.IsZero() == 1
}

// isOnCurve returns true if g is a valid point on the curve.
func (g *G1) isOnCurve() bool {
	var x3, z3, y2 ff.Fp
	y2.Sqr(&g.y)             // y2 = y^2
	y2.Mul(&y2, &g.z)        // y2 = y^2*z
	x3.Sqr(&g.x)             // x3 = x^2
	x3.Mul(&x3, &g.x)        // x3 = x^3
	z3.Sqr(&g.z)             // z3 = z^2
	z3.Mul(&z3, &g.z)        // z3 = z^3
	z3.Mul(&z3, &g1Params.b) // z3 = 4*z^3
	x3.Add(&x3, &z3)         // x3 = x^3 + 4*z^3
	y2.Sub(&y2, &x3)         // y2 = y^2*z - (x^3 + 4*z^3)
	return y2.IsZero() == 1
}

// toAffine updates g with its affine representation.
func (g *G1) toAffine() {
	if g.z.IsZero() != 1 {
		var invZ ff.Fp
		invZ.Inv(&g.z)
		g.x.Mul(&g.x, &invZ)
		g.y.Mul(&g.y, &invZ)
		g.z.SetOne()
	}
}

// EncodeToCurve is a non-uniform encoding from an input byte string (and
// an optional domain separation tag) to elements in G1. This function must not
// be used as a hash function, otherwise use G1.Hash instead.
func (g *G1) Encode(input, dst []byte) {
	const L = 64
	pseudo := group.NewExpanderMD(crypto.SHA256, dst).Expand(input, L)

	bu := new(big.Int).SetBytes(pseudo)
	bu.Mod(bu, new(big.Int).SetBytes(ff.FpOrder()))
	var u ff.Fp
	err := u.SetBytes(bu.FillBytes(make([]byte, ff.FpSize)))
	if err != nil {
		panic(err)
	}
	var q isogG1Point
	q.sswu(&u)
	g.evalIsogG1(&q)
	g.clearCofactor()
}

// Hash produces an element of G1 from the hash of an input byte string and
// an optional domain separation tag. This function is safe to use when a
// random oracle returning points in G1 be required.
func (g *G1) Hash(input, dst []byte) {
	const L = 64
	pseudo := group.NewExpanderMD(crypto.SHA256, dst).Expand(input, 2*L)

	var u0, u1 ff.Fp
	fpOrder := new(big.Int).SetBytes(ff.FpOrder())
	bu := new(big.Int).SetBytes(pseudo[0*L : 1*L])
	bu.Mod(bu, fpOrder)
	err := u0.SetBytes(bu.FillBytes(make([]byte, ff.FpSize)))
	if err != nil {
		panic(err)
	}

	bu.SetBytes(pseudo[1*L : 2*L])
	bu.Mod(bu, fpOrder)
	err = u1.SetBytes(bu.FillBytes(make([]byte, ff.FpSize)))
	if err != nil {
		panic(err)
	}

	var q0, q1 isogG1Point
	q0.sswu(&u0)
	q1.sswu(&u1)
	var p0, p1 G1
	p0.evalIsogG1(&q0)
	p1.evalIsogG1(&q1)
	g.Add(&p0, &p1)
	g.clearCofactor()
}

// G1Generator returns the generator point of G1.
func G1Generator() *G1 {
	var G G1
	G.x.Set(&g1Params.genX)
	G.y.Set(&g1Params.genY)
	G.z.SetOne()
	return &G
}

// affinize converts an entire slice to affine at once
func affinize(points []*G1) {
	if len(points) == 0 {
		return
	}
	ws := make([]ff.Fp, len(points)+1)
	ws[0].SetOne()
	for i := 0; i < len(points); i++ {
		ws[i+1].Mul(&ws[i], &points[i].z)
	}

	w := &ff.Fp{}
	w.Inv(&ws[len(points)])

	zinv := &ff.Fp{}
	for i := len(points) - 1; i >= 0; i-- {
		zinv.Mul(w, &ws[i])
		w.Mul(w, &points[i].z)

		points[i].x.Mul(&points[i].x, zinv)
		points[i].y.Mul(&points[i].y, zinv)
		points[i].z.SetOne()
	}
}
