// Package bls12381 provides bilinear pairings using the BLS12-381 curve.
//
// A pairing system consists of three groups G1 and G2 (adiitive notation) and
// Gt (multiplicative notation) of the same order.
// Scalars can be used interchangeably between groups.
package bls12381

import "github.com/cloudflare/circl/ecc/bls12381/ff"

// Pair calculates the ate-pairing of P and Q.
func Pair(P *G1, Q *G2) *Gt { g := &Gt{}; P.Normalize(); finalExp(g, miller(P, Q)); return g }

func miller(P *G1, Q *G2) *ff.Fp12 {
	f := &ff.Fp12{}
	f.SetOne()
	T := &G2{}
	T.Set(Q)
	l := &line{}
	const lenX = 64
	for i := lenX - 2; i >= 0; i-- {
		f.Sqr(f)
		doubleAndLine(T, l)
		f.Mul(f, l.eval(P))
		// paramX is -2 ^ 63 - 2 ^ 62 - 2 ^ 60 - 2 ^ 57 - 2 ^ 48 - 2 ^ 16
		if (i == 62) || (i == 60) || (i == 57) || (i == 48) || (i == 16) {
			addAndLine(T, T, Q, l)
			f.Mul(f, l.eval(P))
		}
	}
	f.Cjg() // inverts f as paramX is negative.
	return f
}

// line contains the coefficients of a sparse element of Fp12.
// Evaluating the line on P' = (xP',yP') results in
//   g = line(P') = l[0]*xP' + l[1]*yP' + l[2] \in Fp12.
type line [3]ff.Fp2

// eval updates f = f * line(P'), where f lives in Fp12 = Fp6[w]/(w^2-v) and P'
// is the image of P on the twist curve.
func (l *line) eval(P *G1) *ff.Fp12 {
	// Send P \in E to the twist
	//     E    -->        E'
	//  (xP,yP) |-> (xP*w^2,yP*w^3) = (xP',yP')
	//
	// g = line(P') = l[0]*xP' + l[1]*yP' + l[2] \in Fp12.
	//              = l[0]*xP*w^2 + l[1]*yP*w^3 + l[2] \in Fp12.

	// First perform the products: l[0]*xP and l[1]*yP \in Fp2.
	var xP, yP ff.Fp2
	var one ff.Fp12
	one.SetOne()
	xP[0].Set(&P.x)
	yP[0].Set(&P.y)
	l[0].Mul(&l[0], &xP)
	l[1].Mul(&l[1], &yP)

	// Note that w^2=v and w^6=v^3=ξ, so a generic element
	//   a0*w^0 + a1*w^1 + a2*w^2 + a3*w^3 + a4*w^4 + a5*w^5 \in Fp12 = Fp2[w]/(w^6-ξ).
	// is converted to
	//   (a0+a2*v+a4*v^2) + (a1+a3*v+a5*v^2)w \in  Fp12 = Fp6[w]/(w^2-v).
	//
	// Apply such transformation to construct g \in Fp12 = Fp6[w]/(w^2-v).
	var g ff.Fp12
	g[0][0].Set(&l[2])
	g[0][1].Set(&l[0])
	g[1][1].Set(&l[1])
	if g.IsZero() {
		return &one
	}
	return &g
}

func finalExp(g *Gt, f *ff.Fp12) {
	c := &ff.Cyclo6{}
	ff.EasyExponentiation(c, f)
	ff.HardExponentiation(g, c)
}

// ProdPair calculates the product of pairings, i.e., \Prod_i pair(Pi,Qi)^ni.
func ProdPair(P []*G1, Q []*G2, n []*Scalar) *Gt {
	if len(P) != len(Q) || len(P) != len(n) {
		panic("mismatch length of inputs")
	}

	ei := new(ff.Fp12)
	out := new(ff.Fp12)
	out.SetOne()

	for i := range P {
		P[i].Normalize()
		mi := miller(P[i], Q[i])
		ei.Exp(mi, n[i].Bytes())
		out.Mul(out, ei)
	}

	g := &Gt{}
	finalExp(g, out)
	return g
}
