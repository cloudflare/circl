package bls12381

import "github.com/cloudflare/circl/ecc/bls12381/ff"

func doubleAndLine(P *G2, l *line) {
	// Reference:
	//   "Faster Pairing Computations on Curves with High-Degree Twists" by
	//   Costello-Lange-Naehrig. [Sec. 5] (eprint.iacr.org/2009/615).
	//   "Complete addition formulas for prime order elliptic curves" by
	//   Costello-Renes-Batina. [Alg.9] (eprint.iacr.org/2015/1060).
	var R G2
	X, Y, Z := &P.x, &P.y, &P.z
	X3, Y3, Z3 := &R.x, &R.y, &R.z
	isDoubLine := l != nil
	_3B := &g2Params._3b
	var A, B, C, D, E, F, G, T ff.Fp2
	B.Sqr(Y)       // 1. B = Y1^2
	C.Sqr(Z)       // 2. C = Z1^2
	D.Mul(_3B, &C) // 3. D = 3b*C
	F.Add(Y, Z)    // 4. F = (Y1+Z1)
	F.Sqr(&F)      //    F = (Y1+Z1)^2
	F.Sub(&F, &B)  //    F = (Y1+Z1)^2-B
	F.Sub(&F, &C)  //    F = (Y1+Z1)^2-B-C
	if isDoubLine {
		A.Sqr(X)            // 5.  A  = X1^2
		E.Add(X, Y)         //     E  = (X1+Y1)
		E.Sqr(&E)           //     E  = (X1+Y1)^2
		E.Sub(&E, &A)       //     E  = (X1+Y1)^2-A
		E.Sub(&E, &B)       //     E  = (X1+Y1)^2-A-B = 2X*Y
		l[0].Add(&A, &A)    // 5a. l0 = 2A
		l[0].Add(&l[0], &A) //     l0 = 3A = 3X1^2
		l[1] = F            // 5b. l1 = F
		l[1].Neg()          //     l1 = -F = -2Y1Z1
		l[2].Sub(&D, &B)    // 5c. l2 = D-B = 3b*Z1^2-Y1^2
	} else {
		E.Mul(X, Y)   // 5. E = X*Y
		E.Add(&E, &E) //    E = 2X*Y
	}
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
	*P = R
}

func addAndLine(PQ, P, Q *G2, l *line) {
	// Reference:
	//   "Faster Pairing Computations on Curves with High-Degree Twists" by
	//   Costello-Lange-Naehrig. [Sec. 5] (eprint.iacr.org/2009/615).
	//   "Complete addition formulas for prime order elliptic curves" by
	//   Costello-Renes-Batina. [Alg.7] (eprint.iacr.org/2015/1060).
	var R G2
	X1, Y1, Z1 := &P.x, &P.y, &P.z
	X2, Y2, Z2 := &Q.x, &Q.y, &Q.z
	X3, Y3, Z3 := &R.x, &R.y, &R.z
	_3B := &g2Params._3b
	isAddLine := l != nil
	var X1X2, Y1Y2, Z1Z2, _3bZ1Z2 ff.Fp2
	var A, B, C, D, E, F, G ff.Fp2
	t0, t1 := &ff.Fp2{}, &ff.Fp2{}

	X1X2.Mul(X1, X2)
	Y1Y2.Mul(Y1, Y2)
	Z1Z2.Mul(Z1, Z2)
	_3bZ1Z2.Mul(&Z1Z2, _3B)

	A.Add(&X1X2, &X1X2)    // A = 2X1X2
	A.Add(&A, &X1X2)       //   = 3X1X2
	B.Add(&Y1Y2, &_3bZ1Z2) // B = Y1Y2+3bZ1Z2
	C.Sub(&Y1Y2, &_3bZ1Z2) // C = Y1Y2-3bZ1Z2

	t0.Add(X1, Y1)   // t0 = (X1 + Y1)
	D.Add(X2, Y2)    // D  = (X2 + Y2)
	D.Mul(&D, t0)    //    = X1X2 + X1Y2 + X2Y1 + Y1Y2
	D.Sub(&D, &X1X2) //    = X1Y2 + X2Y1 + Y1Y2
	D.Sub(&D, &Y1Y2) //    = X1Y2 + X2Y1

	if isAddLine {
		var EE, FF ff.Fp2
		t0.Mul(Y1, Z2) // t0 = Y1Z2
		t1.Mul(Y2, Z1) // t1 = Y2Z1
		E.Add(t0, t1)  // E  = Y1Z2 + Y2Z1
		EE.Sub(t0, t1) // EE = Y1Z2 - Y2Z1

		t0.Mul(X1, Z2) // t0 = X1Z2
		t1.Mul(X2, Z1) // t1 = X2Z1
		F.Add(t0, t1)  // F  = X1Z2 + X2Z1
		FF.Sub(t0, t1) // FF = X1Z2 - X2Z1

		l[0].Mul(&EE, Z2)   // l0 = (Y1Z2 - Y2Z1)*Z2
		l[0].Neg()          //    = -(Y1Z2 - Y2Z1)*Z2
		l[1].Mul(&FF, Z2)   // l1 = (X1Z2 - X2Z1)*Z2
		t0.Mul(&FF, Y2)     // t0 = (X1Z2 - X2Z1)*Y2
		l[2].Mul(&EE, X2)   // l2 = (Y1Z2 - Y2Z1)*X2
		l[2].Sub(&l[2], t0) //    = (Y1Z2 - Y2Z1)*X2 - (X1Z2 - X2Z1)*Y2
	} else {
		t0.Add(Y1, Z1)   // t0 = (Y1 + Z1)
		t1.Add(Y2, Z2)   // t1 = (Y2 + Z2)
		E.Mul(t0, t1)    // E  = Y1Y2 + Y1Z2 + Y2Z1 + Z1Z2
		E.Sub(&E, &Y1Y2) //    = Y1Z2 + Y2Z1 + Z1Z2
		E.Sub(&E, &Z1Z2) //    = Y1Z2 + Y2Z1

		t0.Add(X1, Z1)   // t0 = (X1 + Z1)
		t1.Add(X2, Z2)   // t1 = (X2 + Z2)
		F.Mul(t0, t1)    // F  = X1X2 + X1Z2 + X2Z1 + Z1Z2
		F.Sub(&F, &X1X2) //    = X1Z2 + X2Z1 + Z1Z2
		F.Sub(&F, &Z1Z2) //    = X1Z2 + X2Z1
	}
	G.Mul(&F, _3B) // G = 3b*F

	t0.Mul(&E, &G) // t0 = E*G
	X3.Mul(&D, &C) // X3 = D*C
	X3.Sub(X3, t0) //    = D*C - E*G

	t0.Mul(&A, &G) // t0 = A*G
	Y3.Mul(&B, &C) // Y3 = B*C
	Y3.Add(Y3, t0) //    = B*C + A*G

	t0.Mul(&A, &D) // t0 = A*D
	Z3.Mul(&E, &B) // Z3 = E*B
	Z3.Add(Z3, t0) //    = E*B + A*D

	*PQ = R
}
