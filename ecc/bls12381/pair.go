package bls12381

import "github.com/cloudflare/circl/ecc/bls12381/ff"

// Pair calculates the ate-pairing of P and Q.
func Pair(P *G1, Q *G2) *Gt { return finalExp(miller(P, Q)) }

func miller(P *G1, Q *G2) *Gt {
	T := &G2{}
	f := &ff.Fp12{}
	l := &line{}

	T.Set(Q)
	f.SetOne()
	for i := lenX - 1; i >= 0; i-- {
		bit := (paramX[i/8] >> uint(i%8)) & 0x1
		f.Sqr(f)
		doubleAndLine(T, l)
		evalLine(f, l, P)
		if bit == 1 {
			addAndLine(T, T, Q, l)
			evalLine(f, l, P)
		}
	}

	var out Gt
	out.g.Set(f)
	return &out
}

type line [3]ff.Fp2

// evalLine updates f = f * l(P)
func evalLine(f *ff.Fp12, l *line, P *G1) {
	//todo
	var g ff.Fp12
	g[0][0].Set(&l[0])
	g[0][1].Set(&l[1])
	g[0][2].Set(&l[2])
	f.Mul(f, &g)
}

func finalExp(g *Gt) *Gt { return nil }
