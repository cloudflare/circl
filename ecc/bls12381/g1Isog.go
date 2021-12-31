package bls12381

import (
	"fmt"

	"github.com/cloudflare/circl/ecc/bls12381/ff"
)

type isogG1Point struct{ x, y, z ff.Fp }

func (p isogG1Point) String() string { return fmt.Sprintf("x: %v\ny: %v\nz: %v", p.x, p.y, p.z) }

// IsOnCurve returns true if g is a valid point on the curve.
func (p *isogG1Point) IsOnCurve() bool {
	var x2, x3, z2, z3, y2 ff.Fp
	y2.Sqr(&p.y)             // y2 = y^2
	y2.Mul(&y2, &p.z)        // y2 = y^2*z
	z2.Sqr(&p.z)             // z2 = z^2
	z3.Mul(&z2, &p.z)        // z3 = z^3
	z3.Mul(&z3, &g1Isog11.b) // z3 = B*z^3
	x2.Sqr(&p.x)             // x2 = x^2
	x3.Mul(&z2, &g1Isog11.a) // x3 = A*z^2
	x3.Add(&x3, &x2)         // x3 = x^2 + A*z^2
	x3.Mul(&x3, &p.x)        // x3 = x^3 + A*x*z^2
	x3.Add(&x3, &z3)         // x3 = x^3 + A*x*z^2 + Bz^3

	return y2.IsEqual(&x3) == 1 && *p != isogG1Point{}
}

// sswu implements the Simplified Shallue-van de Woestijne-Ulas method for
// maping a field element to a point on the isogenous curve.
func (p *isogG1Point) sswu(u *ff.Fp) {
	// Method in Appendix-G.2.1 of
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11
	tv1, tv2, tv3, tv4 := &ff.Fp{}, &ff.Fp{}, &ff.Fp{}, &ff.Fp{}
	xd, x1n, gxd, gx1 := &ff.Fp{}, &ff.Fp{}, &ff.Fp{}, &ff.Fp{}
	y, y1, x2n, y2, xn := &ff.Fp{}, &ff.Fp{}, &ff.Fp{}, &ff.Fp{}, &ff.Fp{}

	tv1.Sqr(u)                       // 1.  tv1 = u^2
	tv3.Mul(&g1sswu.Z, tv1)          // 2.  tv3 = Z * tv1
	tv2.Sqr(tv3)                     // 3.  tv2 = tv3^2
	xd.Add(tv2, tv3)                 // 4.   xd = tv2 + tv3
	tv4.SetOne()                     // 5.  tv4 = 1
	x1n.Add(xd, tv4)                 //     x1n = xd + tv4
	x1n.Mul(x1n, &g1Isog11.b)        // 6.  x1n = x1n * B
	xd.Mul(&g1Isog11.a, xd)          // 7.   xd = A * xd
	xd.Neg()                         //      xd = -xd
	e1 := xd.IsZero()                // 8.   e1 = xd == 0
	tv4.Mul(&g1sswu.Z, &g1Isog11.a)  // 9.  tv4 = Z * A
	xd.CMov(xd, tv4, e1)             //      xd = CMOV(xd, tv4, e1)
	tv2.Sqr(xd)                      // 10. tv2 = xd^2
	gxd.Mul(tv2, xd)                 // 11. gxd = tv2 * xd
	tv2.Mul(&g1Isog11.a, tv2)        // 12. tv2 = A * tv2
	gx1.Sqr(x1n)                     // 13. gx1 = x1n^2
	gx1.Add(gx1, tv2)                // 14. gx1 = gx1 + tv2
	gx1.Mul(gx1, x1n)                // 15. gx1 = gx1 * x1n
	tv2.Mul(&g1Isog11.b, gxd)        // 16. tv2 = B * gxd
	gx1.Add(gx1, tv2)                // 17. gx1 = gx1 + tv2
	tv4.Sqr(gxd)                     // 18. tv4 = gxd^2
	tv2.Mul(gx1, gxd)                // 19. tv2 = gx1 * gxd
	tv4.Mul(tv4, tv2)                // 20. tv4 = tv4 * tv2
	y1.ExpVarTime(tv4, g1sswu.c1[:]) // 21.  y1 = tv4^c1
	y1.Mul(y1, tv2)                  // 22.  y1 = y1 * tv2
	x2n.Mul(tv3, x1n)                // 23. x2n = tv3 * x1n
	y2.Mul(y1, &g1sswu.c2)           // 24.  y2 = y1 * c2
	y2.Mul(y2, tv1)                  // 25.  y2 = y2 * tv1
	y2.Mul(y2, u)                    // 26.  y2 = y2 * u
	tv2.Sqr(y1)                      // 27. tv2 = y1^2
	tv2.Mul(tv2, gxd)                // 28. tv2 = tv2 * gxd
	e2 := tv2.IsEqual(gx1)           // 29.  e2 = tv2 == gx1
	xn.CMov(x2n, x1n, e2)            // 30.  xn = CMOV(x2n, x1n, e2)
	y.CMov(y2, y1, e2)               // 31.   y = CMOV(y2, y1, e2)
	e3 := u.Sgn0() ^ y.Sgn0()        // 32.  e3 = sgn0(u) == sgn0(y)
	*tv1 = *y                        // 33. tv1 = y
	tv1.Neg()                        //     tv1 = -y
	y.CMov(tv1, y, ^e3)              //       y = CMOV(tv1, y, e3)
	p.x = *xn                        // 34. return
	p.y.Mul(y, xd)                   //       (x,y) = (xn/xd, y/1)
	p.z = *xd                        //       (X,Y,Z) = (xn, y*xd, xd)
}

// evalIsogG1 calculates g = g1Isog11(p), where g1Isog11 is an isogeny of
// degree 11 to the curve used in G1.
func (g *G1) evalIsogG1(p *isogG1Point) {
	x, y, z := &p.x, &p.y, &p.z
	t, zi := &ff.Fp{}, &ff.Fp{}
	xNum, xDen, yNum, yDen := &ff.Fp{}, &ff.Fp{}, &ff.Fp{}, &ff.Fp{}

	ixn := len(g1Isog11.xNum) - 1
	ixd := len(g1Isog11.xDen) - 1
	iyn := len(g1Isog11.yNum) - 1
	iyd := len(g1Isog11.yDen) - 1

	*xNum = g1Isog11.xNum[ixn]
	*xDen = g1Isog11.xDen[ixd]
	*yNum = g1Isog11.yNum[iyn]
	*yDen = g1Isog11.yDen[iyd]
	*zi = *z

	for (ixn | ixd | iyn | iyd) != 0 {
		if ixn > 0 {
			ixn--
			t.Mul(zi, &g1Isog11.xNum[ixn])
			xNum.Mul(xNum, x)
			xNum.Add(xNum, t)
		}
		if ixd > 0 {
			ixd--
			t.Mul(zi, &g1Isog11.xDen[ixd])
			xDen.Mul(xDen, x)
			xDen.Add(xDen, t)
		}
		if iyn > 0 {
			iyn--
			t.Mul(zi, &g1Isog11.yNum[iyn])
			yNum.Mul(yNum, x)
			yNum.Add(yNum, t)
		}
		if iyd > 0 {
			iyd--
			t.Mul(zi, &g1Isog11.yDen[iyd])
			yDen.Mul(yDen, x)
			yDen.Add(yDen, t)
		}

		zi.Mul(zi, z)
	}

	g.x.Mul(xNum, yDen)
	g.y.Mul(yNum, xDen)
	g.y.Mul(&g.y, y)
	g.z.Mul(xDen, yDen)
	g.z.Mul(&g.z, z)
}
