package bls12381

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/ecc/bls12381/ff"
)

// G1Size is the length in bytes of an element in G1.
const G1Size = 2 * ff.FpSize

// G1 is a point in the BLS12 curve over Fp.
type G1 struct{ x, y, z ff.Fp }

func (g G1) String() string { return fmt.Sprintf("x: %v\ny: %v\nz: %v", g.x, g.y, g.z) }

// Bytes serializes a G1 element.
func (g *G1) Bytes() []byte { g.Normalize(); return append(g.x.Bytes(), g.y.Bytes()...) }

// SetBytes sets g to the value in bytes, and returns a non-nil error if not in G1
func (g *G1) SetBytes(b []byte) error {
	if len(b) != G1Size {
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

// Set is (TMP).
func (g *G1) Set(P *G1) {
	g.x.Set(&P.x)
	g.y.Set(&P.y)
	g.z.Set(&P.z)
}

// Neg inverts g.
func (g *G1) Neg() { g.y.Neg() }

// SetIdentity assigns g to the identity element.
func (g *G1) SetIdentity() { g.x = ff.Fp{}; g.y.SetOne(); g.z = ff.Fp{} }

// IsOnG1 returns true if the point is in the group G1.
func (g *G1) IsOnG1() bool { return g.IsOnCurve() && g.IsRTorsion() }

// IsIdentity return true if the point is the identity of G1.
func (g *G1) IsIdentity() bool { return g.z.IsZero() }

// IsRTorsion returns true if point is r-torsion.
func (g *G1) IsRTorsion() bool { var P G1; P.scalarMult(ff.ScalarOrder(), g); return P.IsIdentity() }

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
	t0.Sqr(Y)              // 1.  t0 =  Y * Y
	Z3.Add(t0, t0)         // 2.  Z3 = t0 + t0
	Z3.Add(Z3, Z3)         // 3.  Z3 = Z3 + Z3
	Z3.Add(Z3, Z3)         // 4.  Z3 = Z3 + Z3
	t1.Mul(Y, Z)           // 5.  t1 =  Y * Z
	t2.Sqr(Z)              // 6.  t2 =  Z * Z
	t2.Mul(&g1Param3B, t2) // 7.  t2 = b3 * t2
	X3.Mul(t2, Z3)         // 8.  X3 = t2 * Z3
	Y3.Add(t0, t2)         // 9.  Y3 = t0 + t2
	Z3.Mul(t1, Z3)         // 10. Z3 = t1 * Z3
	t1.Add(t2, t2)         // 11. t1 = t2 + t2
	t2.Add(t1, t2)         // 12. t2 = t1 + t2
	t0.Sub(t0, t2)         // 13. t0 = t0 - t2
	Y3.Mul(t0, Y3)         // 14. Y3 = t0 * Y3
	Y3.Add(X3, Y3)         // 15. Y3 = X3 + Y3
	t1.Mul(X, Y)           // 16. t1 =  X * Y
	X3.Mul(t0, t1)         // 17. X3 = t0 * t1
	X3.Add(X3, X3)         // 18. X3 = X3 + X3
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
	var f0, f1, f2, f3, f4 ff.Fp
	t0, t1, t2, t3, t4 := &f0, &f1, &f2, &f3, &f4
	t0.Mul(X1, X2)         // 1.  t0 = X1 * X2
	t1.Mul(Y1, Y2)         // 2.  t1 = Y1 * Y2
	t2.Mul(Z1, Z2)         // 3.  t2 = Z1 * Z2
	t3.Add(X1, Y1)         // 4.  t3 = X1 + Y1
	t4.Add(X2, Y2)         // 5.  t4 = X2 + Y2
	t3.Mul(t3, t4)         // 6.  t3 = t3 * t4
	t4.Add(t0, t1)         // 7.  t4 = t0 + t1
	t3.Sub(t3, t4)         // 8.  t3 = t3 - t4
	t4.Add(Y1, Z1)         // 9.  t4 = Y1 + Z1
	X3.Add(Y2, Z2)         // 10. X3 = Y2 + Z2
	t4.Mul(t4, X3)         // 11. t4 = t4 * X3
	X3.Add(t1, t2)         // 12. X3 = t1 + t2
	t4.Sub(t4, X3)         // 13. t4 = t4 - X3
	X3.Add(X1, Z1)         // 14. X3 = X1 + Z1
	Y3.Add(X2, Z2)         // 15. Y3 = X2 + Z2
	X3.Mul(X3, Y3)         // 16. X3 = X3 * Y3
	Y3.Add(t0, t2)         // 17. Y3 = t0 + t2
	Y3.Sub(X3, Y3)         // 18. Y3 = X3 - Y3
	X3.Add(t0, t0)         // 19. X3 = t0 + t0
	t0.Add(X3, t0)         // 20. t0 = X3 + t0
	t2.Mul(&g1Param3B, t2) // 21. t2 = b3 * t2
	Z3.Add(t1, t2)         // 22. Z3 = t1 + t2
	t1.Sub(t1, t2)         // 23. t1 = t1 - t2
	Y3.Mul(&g1Param3B, Y3) // 24. Y3 = b3 * Y3
	X3.Mul(t4, Y3)         // 25. X3 = t4 * Y3
	t2.Mul(t3, t1)         // 26. t2 = t3 * t1
	X3.Sub(t2, X3)         // 27. X3 = t2 - X3
	Y3.Mul(Y3, t0)         // 28. Y3 = Y3 * t0
	t1.Mul(t1, Z3)         // 29. t1 = t1 * Z3
	Y3.Add(t1, Y3)         // 30. Y3 = t1 + Y3
	t0.Mul(t0, t3)         // 31. t0 = t0 * t3
	Z3.Mul(Z3, t4)         // 32. Z3 = Z3 * t4
	Z3.Add(Z3, t0)         // 33. Z3 = Z3 + t0
	g.Set(&R)
}

// ScalarMult calculates g = kP.
func (g *G1) ScalarMult(k *Scalar, P *G1) { g.scalarMult(k.Bytes(), P) }

func (g *G1) scalarMult(k []byte, P *G1) {
	var Q G1
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

// IsEqual returns true if g and p are equivalent.
func (g *G1) IsEqual(p *G1) bool {
	var lx, rx, ly, ry ff.Fp
	lx.Mul(&g.x, &p.z) // lx = x1*z2
	rx.Mul(&p.x, &g.z) // rx = x2*z1
	lx.Sub(&lx, &rx)   // lx = lx-rx
	ly.Mul(&g.y, &p.z) // ly = y1*z2
	ry.Mul(&p.y, &g.z) // ry = y2*z1
	ly.Sub(&ly, &ry)   // ly = ly-ry
	return lx.IsZero() && ly.IsZero()
}

// IsOnCurve returns true if g is a valid point on the curve.
func (g *G1) IsOnCurve() bool {
	var x3, z3, y2 ff.Fp
	y2.Sqr(&g.y)           // y2 = y^2
	y2.Mul(&y2, &g.z)      // y2 = y^2*z
	x3.Sqr(&g.x)           // x3 = x^2
	x3.Mul(&x3, &g.x)      // x3 = x^3
	z3.Sqr(&g.z)           // z3 = z^2
	z3.Mul(&z3, &g.z)      // z3 = z^3
	z3.Mul(&z3, &g1ParamB) // z3 = 4*z^3
	x3.Add(&x3, &z3)       // x3 = x^3 + 4*z^3
	y2.Sub(&y2, &x3)       // y2 = y^2*z - (x^3 + 4*z^3)
	return y2.IsZero()
}

// Normalize updates g with its affine representation.
func (g *G1) Normalize() {
	if !g.z.IsZero() {
		var invZ ff.Fp
		invZ.Inv(&g.z)
		g.x.Mul(&g.x, &invZ)
		g.y.Mul(&g.y, &invZ)
		g.z.Mul(&g.z, &invZ)
	}
}

// Hash produces an element of G1 from the hash of a message and an optional
// domain separation tag.
func (g *G1) Hash(msg, dst []byte) {
	h := sha256.New()
	for cnt := 0; cnt < 16; cnt++ {
		h.Reset()
		_, _ = h.Write([]byte{byte(cnt)})
		_, _ = h.Write(msg)
		_, _ = h.Write(dst)
		sum := h.Sum(nil)
		xi := new(big.Int).SetBytes(sum)

		var x, gx, y, four ff.Fp
		four.SetUint64(4)
		err := x.SetString(xi.Text(10))
		if err != nil {
			panic("bad string")
		}
		gx.Mul(&x, &x)
		gx.Mul(&gx, &x)
		gx.Add(&gx, &four)
		if y.Sqrt(&gx) {
			g.x.Set(&x)
			g.y.Set(&y)
			g.z.SetOne()
			if !g.IsOnCurve() {
				panic("bad point")
			}
			return
		}
	}
	panic("point not found")
}

// G1Generator returns the generator point of G1.
func G1Generator() *G1 {
	var G G1
	G.x.Set(&g1GenX)
	G.y.Set(&g1GenY)
	G.z.SetOne()
	return &G
}
