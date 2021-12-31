package bls12381

import (
	"fmt"

	"github.com/cloudflare/circl/ecc/bls12381/ff"
)

type isogG2Point struct{ x, y, z ff.Fp2 }

func (p isogG2Point) String() string { return fmt.Sprintf("x: %v\ny: %v\nz: %v", p.x, p.y, p.z) }

// IsOnCurve returns true if g is a valid point on the curve.
func (p *isogG2Point) IsOnCurve() bool {
	var x2, x3, z2, z3, y2 ff.Fp2
	y2.Sqr(&p.y)            // y2 = y^2
	y2.Mul(&y2, &p.z)       // y2 = y^2*z
	z2.Sqr(&p.z)            // z2 = z^2
	z3.Mul(&z2, &p.z)       // z3 = z^3
	z3.Mul(&z3, &g2Isog3.b) // z3 = B*z^3
	x2.Sqr(&p.x)            // x2 = x^2
	x3.Mul(&z2, &g2Isog3.a) // x3 = A*z^2
	x3.Add(&x3, &x2)        // x3 = x^2 + A*z^2
	x3.Mul(&x3, &p.x)       // x3 = x^3 + A*x*z^2
	x3.Add(&x3, &z3)        // x3 = x^3 + A*x*z^2 + Bz^3

	return y2.IsEqual(&x3) == 1 && *p != isogG2Point{}
}

// sswu implements the Simplified Shallue-van de Woestijne-Ulas method for
// maping a field element to a point on the isogenous curve.
func (p *isogG2Point) sswu(u *ff.Fp2) {
	// Method in Appendix-G.2.3 of
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11
	tv1, tv2, tv3, tv4 := &ff.Fp2{}, &ff.Fp2{}, &ff.Fp2{}, &ff.Fp2{}
	tv5, xd, x1n, gxd := &ff.Fp2{}, &ff.Fp2{}, &ff.Fp2{}, &ff.Fp2{}
	gx1, y, xn, gx2 := &ff.Fp2{}, &ff.Fp2{}, &ff.Fp2{}, &ff.Fp2{}

	tv1.Sqr(u)                      // 1.  tv1 = u^2
	tv3.Mul(&g2sswu.Z, tv1)         // 2.  tv3 = Z * tv1
	tv5.Sqr(tv3)                    // 3.  tv5 = tv3^2
	xd.Add(tv5, tv3)                // 4.   xd = tv5 + tv3
	tv2.SetOne()                    // 5.  tv2 = 1
	x1n.Add(xd, tv2)                //     x1n = xd + tv2
	x1n.Mul(x1n, &g2Isog3.b)        // 6.  x1n = x1n * B
	xd.Mul(&g2Isog3.a, xd)          // 7.   xd = A * xd
	xd.Neg()                        //      xd = -xd
	e1 := xd.IsZero()               // 8.   e1 = xd == 0
	tv2.Mul(&g2sswu.Z, &g2Isog3.a)  // 9.  tv2 = Z * A
	xd.CMov(xd, tv2, e1)            //      xd = CMOV(xd, tv2, e1)
	tv2.Sqr(xd)                     // 10. tv2 = xd^2
	gxd.Mul(tv2, xd)                // 11. gxd = tv2 * xd
	tv2.Mul(&g2Isog3.a, tv2)        // 12. tv2 = A * tv2
	gx1.Sqr(x1n)                    // 13. gx1 = x1n^2
	gx1.Add(gx1, tv2)               // 14. gx1 = gx1 + tv2
	gx1.Mul(gx1, x1n)               // 15. gx1 = gx1 * x1n
	tv2.Mul(&g2Isog3.b, gxd)        // 16. tv2 = B * gxd
	gx1.Add(gx1, tv2)               // 17. gx1 = gx1 + tv2
	tv4.Sqr(gxd)                    // 18. tv4 = gxd^2
	tv2.Mul(tv4, gxd)               // 19. tv2 = tv4 * gxd
	tv4.Sqr(tv4)                    // 20. tv4 = tv4^2
	tv2.Mul(tv2, tv4)               // 21. tv2 = tv2 * tv4
	tv2.Mul(tv2, gx1)               // 22. tv2 = tv2 * gx1
	tv4.Sqr(tv4)                    // 23. tv4 = tv4^2
	tv4.Mul(tv2, tv4)               // 24. tv4 = tv2 * tv4
	y.ExpVarTime(tv4, g2sswu.c1[:]) // 25.   y = tv4^c1
	y.Mul(y, tv2)                   // 26.   y = y * tv2
	tv4.Mul(y, &g2sswu.c2)          // 27. tv4 = y * c2
	tv2.Sqr(tv4)                    // 28. tv2 = tv4^2
	tv2.Mul(tv2, gxd)               // 29. tv2 = tv2 * gxd
	e2 := tv2.IsEqual(gx1)          // 30.  e2 = tv2 == gx1
	y.CMov(y, tv4, e2)              // 31.   y = CMOV(y, tv4, e2)
	tv4.Mul(y, &g2sswu.c3)          // 32. tv4 = y * c3
	tv2.Sqr(tv4)                    // 33. tv2 = tv4^2
	tv2.Mul(tv2, gxd)               // 34. tv2 = tv2 * gxd
	e3 := tv2.IsEqual(gx1)          // 35.  e3 = tv2 == gx1
	y.CMov(y, tv4, e3)              // 36.   y = CMOV(y, tv4, e3)
	tv4.Mul(tv4, &g2sswu.c2)        // 37. tv4 = tv4 * c2
	tv2.Sqr(tv4)                    // 38. tv2 = tv4^2
	tv2.Mul(tv2, gxd)               // 39. tv2 = tv2 * gxd
	e4 := tv2.IsEqual(gx1)          // 40.  e4 = tv2 == gx1
	y.CMov(y, tv4, e4)              // 41.   y = CMOV(y, tv4, e4)
	gx2.Mul(gx1, tv5)               // 42. gx2 = gx1 * tv5
	gx2.Mul(gx2, tv3)               // 43. gx2 = gx2 * tv3
	tv5.Mul(y, tv1)                 // 44. tv5 = y * tv1
	tv5.Mul(tv5, u)                 // 45. tv5 = tv5 * u
	tv1.Mul(tv5, &g2sswu.c4)        // 46. tv1 = tv5 * c4
	tv4.Mul(tv1, &g2sswu.c2)        // 47. tv4 = tv1 * c2
	tv2.Sqr(tv4)                    // 48. tv2 = tv4^2
	tv2.Mul(tv2, gxd)               // 49. tv2 = tv2 * gxd
	e5 := tv2.IsEqual(gx2)          // 50.  e5 = tv2 == gx2
	tv1.CMov(tv1, tv4, e5)          // 51. tv1 = CMOV(tv1, tv4, e5)
	tv4.Mul(tv5, &g2sswu.c5)        // 52. tv4 = tv5 * c5
	tv2.Sqr(tv4)                    // 53. tv2 = tv4^2
	tv2.Mul(tv2, gxd)               // 54. tv2 = tv2 * gxd
	e6 := tv2.IsEqual(gx2)          // 55.  e6 = tv2 == gx2
	tv1.CMov(tv1, tv4, e6)          // 56. tv1 = CMOV(tv1, tv4, e6)
	tv4.Mul(tv4, &g2sswu.c2)        // 57. tv4 = tv4 * c2
	tv2.Sqr(tv4)                    // 58. tv2 = tv4^2
	tv2.Mul(tv2, gxd)               // 59. tv2 = tv2 * gxd
	e7 := tv2.IsEqual(gx2)          // 60.  e7 = tv2 == gx2
	tv1.CMov(tv1, tv4, e7)          // 61. tv1 = CMOV(tv1, tv4, e7)
	tv2.Sqr(y)                      // 62. tv2 = y^2
	tv2.Mul(tv2, gxd)               // 63. tv2 = tv2 * gxd
	e8 := tv2.IsEqual(gx1)          // 64.  e8 = tv2 == gx1
	y.CMov(tv1, y, e8)              // 65.   y = CMOV(tv1, y, e8)
	tv2.Mul(tv3, x1n)               // 66. tv2 = tv3 * x1n
	xn.CMov(tv2, x1n, e8)           // 67.  xn = CMOV(tv2, x1n, e8)
	e9 := 1 ^ u.Sgn0() ^ y.Sgn0()   // 68.  e9 = sgn0(u) == sgn0(y)
	*tv1 = *y                       // 69. tv1 = y
	tv1.Neg()                       //     tv1 = -y
	y.CMov(tv1, y, e9)              //       y = CMOV(tv1, y, e9)
	p.x = *xn                       // 70. return
	p.y.Mul(y, xd)                  //       (x,y) = (xn/xd, y/1)
	p.z = *xd                       //       (X,Y,Z) = (xn, y*xd, xd)
}

// evalIsogG2 calculates g = g2Isog3(p), where g2Isog3 is an isogeny of
// degree 3 to the curve used in G2.
func (g *G2) evalIsogG2(p *isogG2Point) {
	x, y, z := &p.x, &p.y, &p.z
	t, zi := &ff.Fp2{}, &ff.Fp2{}
	xNum, xDen, yNum, yDen := &ff.Fp2{}, &ff.Fp2{}, &ff.Fp2{}, &ff.Fp2{}

	ixn := len(g2Isog3.xNum) - 1
	ixd := len(g2Isog3.xDen) - 1
	iyn := len(g2Isog3.yNum) - 1
	iyd := len(g2Isog3.yDen) - 1

	*xNum = g2Isog3.xNum[ixn]
	*xDen = g2Isog3.xDen[ixd]
	*yNum = g2Isog3.yNum[iyn]
	*yDen = g2Isog3.yDen[iyd]
	*zi = *z

	for (ixn | ixd | iyn | iyd) != 0 {
		if ixn > 0 {
			ixn--
			t.Mul(zi, &g2Isog3.xNum[ixn])
			xNum.Mul(xNum, x)
			xNum.Add(xNum, t)
		}
		if ixd > 0 {
			ixd--
			t.Mul(zi, &g2Isog3.xDen[ixd])
			xDen.Mul(xDen, x)
			xDen.Add(xDen, t)
		}
		if iyn > 0 {
			iyn--
			t.Mul(zi, &g2Isog3.yNum[iyn])
			yNum.Mul(yNum, x)
			yNum.Add(yNum, t)
		}
		if iyd > 0 {
			iyd--
			t.Mul(zi, &g2Isog3.yDen[iyd])
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
