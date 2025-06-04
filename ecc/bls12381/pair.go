package bls12381

import "github.com/cloudflare/circl/ecc/bls12381/ff"

// Pair calculates the ate-pairing of P and Q.
func Pair(P *G1, Q *G2) *Gt {
	affP := *P
	affP.toAffine()
	mi := &ff.Fp12{}
	miller(mi, &affP, Q)
	e := &Gt{}
	finalExp(e, mi)
	return e
}

func miller(f *ff.Fp12, P *G1, Q *G2) {
	g := &ff.LineValue{}
	acc := &ff.Fp12Cubic{}
	acc.SetOne()
	T := &G2{}
	*T = *Q
	l := &line{}
	const lenX = 64
	for i := lenX - 2; i >= 0; i-- {
		acc.Sqr(acc)
		doubleAndLine(T, l)
		evalLine(g, l, P)
		acc.MulLine(acc, g)
		// paramX is -2 ^ 63 - 2 ^ 62 - 2 ^ 60 - 2 ^ 57 - 2 ^ 48 - 2 ^ 16
		if (i == 62) || (i == 60) || (i == 57) || (i == 48) || (i == 16) {
			addAndLine(T, T, Q, l)
			evalLine(g, l, P)
			acc.MulLine(acc, g)
		}
	}
	f.FromFp12Cubic(acc)
	f.Cjg() // inverts f as paramX is negative.
}

// line contains the coefficients of a sparse element of Fp12.
// Evaluating the line on P' = (xP',yP') results in
//
//	f = evalLine(P') = l[0]*xP' + l[1]*yP' + l[2] \in Fp12.
type line [3]ff.Fp2

// evalLine updates f = f * line(P'), where f lives in Fp12 = Fp6[w]/(w^2-v)
// and P' is the image of P on the twist curve.
func evalLine(f *ff.LineValue, l *line, P *G1) {
	// Send P \in E to the twist
	//     E    -->        E'
	//  (xP,yP) |-> (xP*w^2,yP*w^3) = (xP',yP')
	//
	// f = line(P') = l[0]*xP' + l[1]*yP' + l[2] \in Fp12.
	//              = l[0]*xP*w^2 + l[1]*yP*w^3 + l[2] \in Fp12.

	// First perform the products: l[0]*xP and l[1]*yP \in Fp2.
	var xP, yP ff.Fp2
	xP[0] = P.x
	yP[0] = P.y
	f[1].Mul(&l[0], &xP)
	f[2].Mul(&l[1], &yP)
	f[0] = l[2]

	if f.IsZero() == 1 {
		f.SetOne()
	}
}

func finalExp(g *Gt, f *ff.Fp12) {
	c := &ff.Cyclo6{}
	ff.EasyExponentiation(c, f)
	ff.HardExponentiation(&g.i, c)
}

// ProdPair calculates the product of pairings, i.e., \Prod_i pair(ni*Pi,Qi).
func ProdPair(P []*G1, Q []*G2, n []*Scalar) *Gt {
	if len(P) != len(Q) || len(P) != len(n) {
		panic("mismatch length of inputs")
	}

	scaled := make([]*G1, len(P))
	for i := range P {
		scaled[i] = new(G1)
		scaled[i].ScalarMult(n[i], P[i])
	}

	affineP := affinize(scaled)

	mi := new(ff.Fp12)
	out := new(ff.Fp12)
	out.SetOne()

	for i := range affineP {
		miller(mi, &affineP[i], Q[i])
		out.Mul(out, mi)
	}

	e := &Gt{}
	finalExp(e, out)
	return e
}

// ProdPairFrac computes the product e(P, Q)^sign where sign is 1 or -1
func ProdPairFrac(P []*G1, Q []*G2, signs []int) *Gt {
	if len(P) != len(Q) || len(P) != len(signs) {
		panic("mismatch length of inputs")
	}

	mi := new(ff.Fp12)
	out := new(ff.Fp12)
	out.SetOne()

	affineP := affinize(P)
	for i := range affineP {
		if signs[i] == -1 {
			affineP[i].Neg()
		}
		miller(mi, &affineP[i], Q[i])
		out.Mul(mi, out)
	}

	e := &Gt{}
	finalExp(e, out)
	return e
}
