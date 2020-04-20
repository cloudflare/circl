package bls12381

import "fmt"

// G2 is a point in the twist of the BLS12 curve over Fp2.
type G2 struct {
	x fp2
	y fp2
	z fp2
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
func (g *G2) Double() {
	// Reference:
	//   "Complete addition formulas for prime order elliptic curves" by
	//   Costello-Renes-Batina. [Alg.9] (eprint.iacr.org/2015/1060).
	var R G2
	X, Y, Z := &g.x, &g.y, &g.z
	X3, Y3, Z3 := &R.x, &R.y, &R.z
	var f0, f1, f2 fp2
	t0, t1, t2 := &f0, &f1, &f2
	t0.Sqr(Y)              // 1.  t0 ←  Y · Y
	Z3.Add(t0, t0)         // 2.  Z3 ← t0 + t0
	Z3.Add(Z3, Z3)         // 3.  Z3 ← Z3 + Z3
	Z3.Add(Z3, Z3)         // 4.  Z3 ← Z3 + Z3
	t1.Mul(Y, Z)           // 5.  t1 ←  Y · Z
	t2.Sqr(Z)              // 6.  t2 ←  Z · Z
	t2.Mul(&g2Param3B, t2) // 7.  t2 ← b3 · t2
	X3.Mul(t2, Z3)         // 8.  X3 ← t2 · Z3
	Y3.Add(t0, t2)         // 9.  Y3 ← t0 + t2
	Z3.Mul(t1, Z3)         // 10. Z3 ← t1 · Z3
	t1.Add(t2, t2)         // 11. t1 ← t2 + t2
	t2.Add(t1, t2)         // 12. t2 ← t1 + t2
	t0.Sub(t0, t2)         // 13. t0 ← t0 − t2
	Y3.Mul(t0, Y3)         // 14. Y3 ← t0 · Y3
	Y3.Add(X3, Y3)         // 15. Y3 ← X3 + Y3
	t1.Mul(X, Y)           // 16. t1 ←  X · Y
	X3.Mul(t0, t1)         // 17. X3 ← t0 · t1
	X3.Add(X3, X3)         // 18. X3 ← X3 + X3
	g.Set(&R)
}

// Add is
func (g *G2) Add(P, Q *G2) {
	// Reference:
	//   "Complete addition formulas for prime order elliptic curves" by
	//   Costello-Renes-Batina. [Alg.7] (eprint.iacr.org/2015/1060).
	var R G2
	X1, Y1, Z1 := &P.x, &P.y, &P.z
	X2, Y2, Z2 := &Q.x, &Q.y, &Q.z
	X3, Y3, Z3 := &R.x, &R.y, &R.z
	var f0, f1, f2, f3, f4 fp2
	t0, t1, t2, t3, t4 := &f0, &f1, &f2, &f3, &f4
	t0.Mul(X1, X2)         // 1.  t0 ← X1 · X2
	t1.Mul(Y1, Y2)         // 2.  t1 ← Y1 · Y2
	t2.Mul(Z1, Z2)         // 3.  t2 ← Z1 · Z2
	t3.Add(X1, Y1)         // 4.  t3 ← X1 + Y1
	t4.Add(X2, Y2)         // 5.  t4 ← X2 + Y2
	t3.Mul(t3, t4)         // 6.  t3 ← t3 · t4
	t4.Add(t0, t1)         // 7.  t4 ← t0 + t1
	t3.Sub(t3, t4)         // 8.  t3 ← t3 − t4
	t4.Add(Y1, Z1)         // 9.  t4 ← Y1 + Z1
	X3.Add(Y2, Z2)         // 10. X3 ← Y2 + Z2
	t4.Mul(t4, X3)         // 11. t4 ← t4 · X3
	X3.Add(t1, t2)         // 12. X3 ← t1 + t2
	t4.Sub(t4, X3)         // 13. t4 ← t4 − X3
	X3.Add(X1, Z1)         // 14. X3 ← X1 + Z1
	Y3.Add(X2, Z2)         // 15. Y3 ← X2 + Z2
	X3.Mul(X3, Y3)         // 16. X3 ← X3 · Y3
	Y3.Add(t0, t2)         // 17. Y3 ← t0 + t2
	Y3.Sub(X3, Y3)         // 18. Y3 ← X3 − Y3
	X3.Add(t0, t0)         // 19. X3 ← t0 + t0
	t0.Add(X3, t0)         // 20. t0 ← X3 + t0
	t2.Mul(&g2Param3B, t2) // 21. t2 ← b3 · t2
	Z3.Add(t1, t2)         // 22. Z3 ← t1 + t2
	t1.Sub(t1, t2)         // 23. t1 ← t1 − t2
	Y3.Mul(&g2Param3B, Y3) // 24. Y3 ← b3 · Y3
	X3.Mul(t4, Y3)         // 25. X3 ← t4 · Y3
	t2.Mul(t3, t1)         // 26. t2 ← t3 · t1
	X3.Sub(t2, X3)         // 27. X3 ← t2 − X3
	Y3.Mul(Y3, t0)         // 28. Y3 ← Y3 · t0
	t1.Mul(t1, Z3)         // 29. t1 ← t1 · Z3
	Y3.Add(t1, Y3)         // 30. Y3 ← t1 + Y3
	t0.Mul(t0, t3)         // 31. t0 ← t0 · t3
	Z3.Mul(Z3, t4)         // 32. Z3 ← Z3 · t4
	Z3.Add(Z3, t0)         // 33. Z3 ← Z3 + t0
	g.Set(&R)
}

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
	var lx, rx, ly, ry fp2
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
	var x3, z3, y2 fp2
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
	var invZ fp2
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
