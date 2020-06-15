package bls12381

import (
	"github.com/cloudflare/circl/ecc/bls12381/ff"
)

// Pair calculates the ate-pairing of P and Q.
func Pair(P *G1, Q *G2) *Gt { return finalExp(miller(P, Q)) }

const lenX = 64

// paramX is -2 ^ 63 - 2 ^ 62 - 2 ^ 60 - 2 ^ 57 - 2 ^ 48 - 2 ^ 16

func miller(P *G1, Q *G2) *Gt {
	T := &G2{}
	f := &ff.Fp12{}
	l := &line{}

	T.Set(Q)
	f.SetOne()
	for i := lenX - 2; i >= 0; i-- {
		f.Sqr(f)
		doubleAndLine(T, l)
		l.eval(f, P)
		if (i == 62) || (i == 60) || (i == 57) || (i == 48) || (i == 16) {
			addAndLine(T, T, Q, l)
			l.eval(f, P)
		}
	}
	f.Cjg()

	var out Gt
	out.g.Set(f)
	return &out
}

// line contains the coefficients of a sparse element of Fp12.
// Evaluating the line on P = (xP,yP) results in
//   line(xP,yP) = (l0*yP)w^0 + (l1*xP)w^1 + (l3)w^3 \in Fp2[W]/(W^6-w).
type line struct{ l0, l1, l3 ff.Fp2 }

// eval updates f = f * line(P), where f lives in Fp12 = Fp6[w]/(w^2-v).
func (l *line) eval(f *ff.Fp12, P *G1) {
	// First, construct the line(p) as an element of Fp12 = Fp6[w]/(w^2-v).
	var xP, yP ff.Fp2
	xP[0].Set(&P.x)
	yP[0].Set(&P.y)
	l.l0.Mul(&l.l0, &yP)
	l.l1.Mul(&l.l1, &xP)
	// Then, multiply (in-place) by f.
	var g ff.Fp12
	g[0][0].Set(&l.l3)
	g[0][1].Set(&l.l1)
	g[1][1].Set(&l.l0)
	f.Mul(f, &g)
}

func finalExp(g *Gt) *Gt { return g }
