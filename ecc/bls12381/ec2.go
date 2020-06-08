package bls12381

import "github.com/cloudflare/circl/ecc/bls12381/ff"

func doubleAndLine(P *G2, l *line) {
	// Reference:
	//   "Faster Pairing Computations on Curves with High-Degree Twists" by
	//   Costello-Lange-Naehrig. [Sec. 5] (eprint.iacr.org/2009/615).
	//   "Complete addition formulas for prime order elliptic curves" by
	//   Costello-Renes-Batina. [Alg.7] (eprint.iacr.org/2015/1060).
	var R G2
	X, Y, Z := &P.x, &P.y, &P.z
	X3, Y3, Z3 := &R.x, &R.y, &R.z
	isDoubLine := l != nil
	_3B := &g2Param3B
	var A, B, C, D, E, F, G, T ff.Fp2
	B.Sqr(Y)       // 1.  B  = Y1^2
	C.Sqr(Z)       // 2.  C  = Z1^2
	D.Mul(_3B, &C) // 3.  D  = 3b*C
	if isDoubLine {
		A.Sqr(X)      // 4.  A  = X1^2
		E.Add(X, Y)   //     E  = (X1+Y1)
		E.Sqr(&E)     //     E  = (X1+Y1)^2
		E.Sub(&E, &A) //     E  = (X1+Y1)^2-A
		E.Sub(&E, &B) //     E  = (X1+Y1)^2-A-B
	} else {
		E.Mul(X, Y)   // 4.  E = X*Y
		E.Add(&E, &E) //     E = 2X*Y
	}
	F.Add(Y, Z)    // 5.  F  = (Y1+Z1)
	F.Sqr(&F)      //     F  = (Y1+Z1)^2
	F.Sub(&F, &B)  //     F  = (Y1+Z1)^2-B
	F.Sub(&F, &C)  //     F  = (Y1+Z1)^2-B-C
	T.Add(&D, &D)  // 6.  T  = 2D
	G.Add(&T, &D)  // 7.  G  = 3D
	X3.Sub(&B, &G) // 8.  X3 = (B-G)
	X3.Mul(X3, &E) //     X3 = E*(B-G)
	T.Sqr(&T)      // 9 .  T = 4D^2
	Y3.Add(&B, &G) // 10. Y3 = (B+G)
	Y3.Sqr(Y3)     //     Y3 = (B+G)^2
	Y3.Sub(Y3, &T) //     Y3 = (B+G)^2-4D^2
	Y3.Sub(Y3, &T) //     Y3 = (B+G)^2-8D^2
	Y3.Sub(Y3, &T) //     Y3 = (B+G)^2-12D^2
	Z3.Mul(&B, &F) // 11. Z3 = B*F
	Z3.Add(Z3, Z3) //     Z3 = 2B*F
	Z3.Add(Z3, Z3) //     Z3 = 4B*F
	P.Set(&R)
	if isDoubLine {
		l[2].Add(&A, &A)    // 13. l2 = 2A
		l[2].Add(&l[2], &A) //     l2 = 3A
		l[1].Set(&F)        // 14. l1 = F
		l[1].Neg()          //     l1 = -F
		l[0].Sub(&D, &B)    // 15. l0 = D-B
	}
}

func addAndLine(PQ, P, Q *G2, l *line) {
	// Reference:
	//   "Complete addition formulas for prime order elliptic curves" by
	//   Costello-Renes-Batina. [Alg.7] (eprint.iacr.org/2015/1060).
	var R G2
	X1, Y1, Z1 := &P.x, &P.y, &P.z
	X2, Y2, Z2 := &Q.x, &Q.y, &Q.z
	X3, Y3, Z3 := &R.x, &R.y, &R.z
	_3B := &g2Param3B
	isAddLine := l != nil
	var f0, f1, f2, f3, f4 ff.Fp2
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
	PQ.Set(&R)
	if isAddLine {

	}
}
