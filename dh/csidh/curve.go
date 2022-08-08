package csidh

// xAdd implements differential arithmetic in P^1 for Montgomery
// curves E(x): x^3 + A*x^2 + x by using x-coordinate only arithmetic.
//
//	x(PaQ) = x(P) + x(Q) by using x(P-Q)
//
// This algorithms is correctly defined only for cases when
// P!=inf, Q!=inf, P!=Q and P!=-Q.
func xAdd(PaQ, P, Q, PdQ *point) {
	var t0, t1, t2, t3 fp
	addRdc(&t0, &P.x, &P.z)
	subRdc(&t1, &P.x, &P.z)
	addRdc(&t2, &Q.x, &Q.z)
	subRdc(&t3, &Q.x, &Q.z)
	mulRdc(&t0, &t0, &t3)
	mulRdc(&t1, &t1, &t2)
	addRdc(&t2, &t0, &t1)
	subRdc(&t3, &t0, &t1)
	mulRdc(&t2, &t2, &t2) // sqr
	mulRdc(&t3, &t3, &t3) // sqr
	mulRdc(&PaQ.x, &PdQ.z, &t2)
	mulRdc(&PaQ.z, &PdQ.x, &t3)
}

// xDbl implements point doubling on a Montgomery curve
// E(x): x^3 + A*x^2 + x by using x-coordinate onlyh arithmetic.
//
//	x(Q) = [2]*x(P)
//
// It is correctly defined for all P != inf.
func xDbl(Q, P, A *point) {
	var t0, t1, t2 fp
	addRdc(&t0, &P.x, &P.z)
	mulRdc(&t0, &t0, &t0) // sqr
	subRdc(&t1, &P.x, &P.z)
	mulRdc(&t1, &t1, &t1) // sqr
	subRdc(&t2, &t0, &t1)
	mulRdc(&t1, &four, &t1)
	mulRdc(&t1, &t1, &A.z)
	mulRdc(&Q.x, &t0, &t1)
	addRdc(&t0, &A.z, &A.z)
	addRdc(&t0, &t0, &A.x)
	mulRdc(&t0, &t0, &t2)
	addRdc(&t0, &t0, &t1)
	mulRdc(&Q.z, &t0, &t2)
}

// xDblAdd implements combined doubling of point P
// and addition of points P and Q on a Montgomery curve
// E(x): x^3 + A*x^2 + x by using x-coordinate onlyh arithmetic.
//
//	x(PaP) = x(2*P)
//	x(PaQ) = x(P+Q)
func xDblAdd(PaP, PaQ, P, Q, PdQ *point, A24 *coeff) {
	var t0, t1, t2 fp

	addRdc(&t0, &P.x, &P.z)
	subRdc(&t1, &P.x, &P.z)
	mulRdc(&PaP.x, &t0, &t0)
	subRdc(&t2, &Q.x, &Q.z)
	addRdc(&PaQ.x, &Q.x, &Q.z)
	mulRdc(&t0, &t0, &t2)
	mulRdc(&PaP.z, &t1, &t1)
	mulRdc(&t1, &t1, &PaQ.x)
	subRdc(&t2, &PaP.x, &PaP.z)
	mulRdc(&PaP.z, &PaP.z, &A24.c)
	mulRdc(&PaP.x, &PaP.x, &PaP.z)
	mulRdc(&PaQ.x, &A24.a, &t2)
	subRdc(&PaQ.z, &t0, &t1)
	addRdc(&PaP.z, &PaP.z, &PaQ.x)
	addRdc(&PaQ.x, &t0, &t1)
	mulRdc(&PaP.z, &PaP.z, &t2)
	mulRdc(&PaQ.z, &PaQ.z, &PaQ.z)
	mulRdc(&PaQ.x, &PaQ.x, &PaQ.x)
	mulRdc(&PaQ.z, &PaQ.z, &PdQ.x)
	mulRdc(&PaQ.x, &PaQ.x, &PdQ.z)
}

// cswappoint swaps P1 with P2 in constant time. The 'choice'
// parameter must have a value of either 1 (results
// in swap) or 0 (results in no-swap).
func cswappoint(P1, P2 *point, choice uint8) {
	cswap512(&P1.x, &P2.x, choice)
	cswap512(&P1.z, &P2.z, choice)
}

// xMul implements point multiplication with left-to-right Montgomery
// adder. co is A coefficient of x^3 + A*x^2 + x curve. k must be > 0
//
// Non-constant time!
func xMul(kP, P *point, co *coeff, k *fp) {
	var A24 coeff
	var Q point
	var j uint
	A := point{x: co.a, z: co.c}
	R := *P

	// Precompyte A24 = (A+2C:4C) => (A24.x = A.x+2A.z; A24.z = 4*A.z)
	addRdc(&A24.a, &co.c, &co.c)
	addRdc(&A24.a, &A24.a, &co.a)
	mulRdc(&A24.c, &co.c, &four)

	// Skip initial 0 bits.
	for j = 511; j > 0; j-- {
		// performance hit from making it constant-time is actually
		// quite big, so... unsafe branch for now
		if uint8(k[j>>6]>>(j&63)&1) != 0 {
			break
		}
	}

	xDbl(&Q, P, &A)
	prevBit := uint8(1)
	for i := j; i > 0; {
		i--
		bit := uint8(k[i>>6] >> (i & 63) & 1)
		cswappoint(&Q, &R, prevBit^bit)
		xDblAdd(&Q, &R, &Q, &R, P, &A24)
		prevBit = bit
	}
	cswappoint(&Q, &R, uint8(k[0]&1))
	*kP = Q
}

// xIso computes the isogeny with kernel point kern of a given order
// kernOrder. Returns the new curve coefficient co and the image img.
//
// During computation function switches between Montgomery and twisted
// Edwards curves in order to compute image curve parameters faster.
// This technique is described by Meyer and Reith in ia.cr/2018/782.
//
// Non-constant time.
func xIso(img *point, co *coeff, kern *point, kernOrder uint64) {
	var t0, t1, t2, S, D fp
	var Q, prod point
	var coEd coeff
	M := [3]point{*kern}

	// Compute twisted Edwards coefficients
	// coEd.a = co.a + 2*co.c
	// coEd.c = co.a - 2*co.c
	// coEd.a*X^2 + Y^2 = 1 + coEd.c*X^2*Y^2
	addRdc(&coEd.c, &co.c, &co.c)
	addRdc(&coEd.a, &co.a, &coEd.c)
	subRdc(&coEd.c, &co.a, &coEd.c)

	// Transfer point to twisted Edwards YZ-coordinates
	// (X:Z)->(Y:Z) = (X-Z : X+Z)
	addRdc(&S, &img.x, &img.z)
	subRdc(&D, &img.x, &img.z)

	subRdc(&prod.x, &kern.x, &kern.z)
	addRdc(&prod.z, &kern.x, &kern.z)

	mulRdc(&t1, &prod.x, &S)
	mulRdc(&t0, &prod.z, &D)
	addRdc(&Q.x, &t0, &t1)
	subRdc(&Q.z, &t0, &t1)

	xDbl(&M[1], kern, &point{x: co.a, z: co.c})

	// NOTE: Not constant time.
	for i := uint64(1); i < kernOrder>>1; i++ {
		if i >= 2 {
			xAdd(&M[i%3], &M[(i-1)%3], kern, &M[(i-2)%3])
		}
		subRdc(&t1, &M[i%3].x, &M[i%3].z)
		addRdc(&t0, &M[i%3].x, &M[i%3].z)
		mulRdc(&prod.x, &prod.x, &t1)
		mulRdc(&prod.z, &prod.z, &t0)
		mulRdc(&t1, &t1, &S)
		mulRdc(&t0, &t0, &D)
		addRdc(&t2, &t0, &t1)
		mulRdc(&Q.x, &Q.x, &t2)
		subRdc(&t2, &t0, &t1)
		mulRdc(&Q.z, &Q.z, &t2)
	}

	mulRdc(&Q.x, &Q.x, &Q.x)
	mulRdc(&Q.z, &Q.z, &Q.z)
	mulRdc(&img.x, &img.x, &Q.x)
	mulRdc(&img.z, &img.z, &Q.z)

	// coEd.a^kernOrder and coEd.c^kernOrder
	modExpRdc64(&coEd.a, &coEd.a, kernOrder)
	modExpRdc64(&coEd.c, &coEd.c, kernOrder)

	// prod^8
	mulRdc(&prod.x, &prod.x, &prod.x)
	mulRdc(&prod.x, &prod.x, &prod.x)
	mulRdc(&prod.x, &prod.x, &prod.x)
	mulRdc(&prod.z, &prod.z, &prod.z)
	mulRdc(&prod.z, &prod.z, &prod.z)
	mulRdc(&prod.z, &prod.z, &prod.z)

	// Compute image curve params
	mulRdc(&coEd.c, &coEd.c, &prod.x)
	mulRdc(&coEd.a, &coEd.a, &prod.z)

	// Convert curve coefficients back to Montgomery
	addRdc(&co.a, &coEd.a, &coEd.c)
	subRdc(&co.c, &coEd.a, &coEd.c)
	addRdc(&co.a, &co.a, &co.a)
}

// montEval evaluates x^3 + Ax^2 + x.
func montEval(res, A, x *fp) {
	var t fp

	*res = *x
	mulRdc(res, res, res)
	mulRdc(&t, A, x)
	addRdc(res, res, &t)
	addRdc(res, res, &one)
	mulRdc(res, res, x)
}
