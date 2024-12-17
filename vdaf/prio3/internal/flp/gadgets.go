package flp

import (
	"github.com/cloudflare/circl/vdaf/prio3/arith"
	"github.com/cloudflare/circl/vdaf/prio3/arith/fp128"
	"github.com/cloudflare/circl/vdaf/prio3/arith/fp64"
	"github.com/cloudflare/circl/vdaf/prio3/internal/cursor"
)

type Gadget[
	P arith.Poly[P, E], V arith.Vec[V, E], E arith.Elt, F arith.Fp[E],
] interface {
	// Arity is the number of input wires.
	Arity() uint
	// Degree is the arithmetic degree of the gadget circuit.
	Degree() uint
	// Eval is evaluates the gadget over the given inputs.
	Eval(out *E, in V)
	// EvalPoly is evaluates the circuit over the polynomial ring of the field.
	EvalPoly(out P, in []P)
}

type gadgetMul struct{}

func (gadgetMul) Arity() uint  { return 2 }
func (gadgetMul) Degree() uint { return 2 }

type GadgetMulFp64 struct{ gadgetMul }

func (GadgetMulFp64) Eval(out *fp64.Fp, in fp64.Vec) {
	out.Mul(&in[0], &in[1])
}

func (GadgetMulFp64) EvalPoly(out fp64.Poly, in []fp64.Poly) {
	out.Mul(in[0], in[1])
}

type gadgetMulFp128 struct{ gadgetMul }

func (gadgetMulFp128) Eval(out *fp128.Fp, in fp128.Vec) {
	out.Mul(&in[0], &in[1])
}

func (gadgetMulFp128) EvalPoly(out fp128.Poly, in []fp128.Poly) {
	out.Mul(in[0], in[1])
}

// PolyEval gadget for p(x) = x^2-x.
type GadgetPolyEvalx2x struct{}

func (GadgetPolyEvalx2x) Arity() uint  { return 1 }
func (GadgetPolyEvalx2x) Degree() uint { return 2 }
func (GadgetPolyEvalx2x) Eval(out *fp64.Fp, in fp64.Vec) {
	out.Sqr(&in[0])
	out.SubAssign(&in[0])
}

func (GadgetPolyEvalx2x) EvalPoly(out fp64.Poly, in []fp64.Poly) {
	out.Sqr(in[0])
	outShort := out[:len(in[0])]
	outShort.SubAssign(in[0])
	out.Strip()
}

type GadgetParallelSum struct {
	inner gadgetMulFp128
	Count uint
}

func (g GadgetParallelSum) Arity() uint  { return g.inner.Arity() * g.Count }
func (g GadgetParallelSum) Degree() uint { return g.inner.Degree() }
func (g GadgetParallelSum) Eval(out *fp128.Fp, in fp128.Vec) {
	inCur := cursor.New(in)
	arity := g.inner.Arity()
	var e fp128.Fp
	for range g.Count {
		g.inner.Eval(&e, inCur.Next(arity))
		out.AddAssign(&e)
	}
}

func (g GadgetParallelSum) EvalPoly(out fp128.Poly, in []fp128.Poly) {
	inCur := cursor.New(in)
	arity := g.inner.Arity()
	e := arith.NewPoly[fp128.Poly](uint(len(out) - 1))
	for range g.Count {
		g.inner.EvalPoly(e, inCur.Next(arity))
		out.AddAssign(e)
	}

	out.Strip()
}

type wrapperGadget[
	G Gadget[P, V, E, F],
	P arith.Poly[P, E], V arith.Vec[V, E], E arith.Elt, F arith.Fp[E],
] struct {
	inner    G
	wires    V
	p, log2p uint
	k        uint
}

func (g *wrapperGadget[G, P, V, E, F]) Arity() uint            { return g.inner.Arity() }
func (g *wrapperGadget[G, P, V, E, F]) Degree() uint           { return g.inner.Degree() }
func (g *wrapperGadget[G, P, V, E, F]) EvalPoly(out P, in []P) { g.inner.EvalPoly(out, in) }
func (g *wrapperGadget[G, P, V, E, F]) eval(input V) {
	g.k++
	wiresCur := cursor.New(g.wires)
	for i := range input {
		wiresCur.Next(g.p)[g.k] = input[i]
	}
}

type ProveGadget[
	G Gadget[P, V, E, F],
	P arith.Poly[P, E], V arith.Vec[V, E], E arith.Elt, F arith.Fp[E],
] struct {
	wrapperGadget[G, P, V, E, F]
}

func (g *ProveGadget[G, P, V, E, F]) Eval(out *E, input V) {
	g.wrapperGadget.eval(input)
	g.inner.Eval(out, input)
}

type QueryGadget[
	G Gadget[P, V, E, F],
	P arith.Poly[P, E], V arith.Vec[V, E], E arith.Elt, F arith.Fp[E],
] struct {
	poly          P
	alpha, alphaK E
	wrapperGadget[G, P, V, E, F]
}

func (g *QueryGadget[G, P, V, E, F]) Eval(out *E, input V) {
	g.wrapperGadget.eval(input)
	F(&g.alphaK).MulAssign(&g.alpha)
	*out = g.poly.Evaluate(&g.alphaK)
}
