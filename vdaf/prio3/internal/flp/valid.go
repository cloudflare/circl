package flp

import (
	"github.com/cloudflare/circl/math"
	"github.com/cloudflare/circl/vdaf/prio3/arith"
	"github.com/cloudflare/circl/vdaf/prio3/arith/fp128"
	"github.com/cloudflare/circl/vdaf/prio3/internal/cursor"
)

type Params struct {
	MeasurementLen uint
	JointRandLen   uint
	EvalOutputLen  uint
	OutputLen      uint
}

func (p Params) MeasurementLength() uint { return p.MeasurementLen }
func (p Params) JointRandLength() uint   { return p.JointRandLen }
func (p Params) OutputLength() uint      { return p.OutputLen }
func (p Params) EvalOutputLength() uint  { return p.EvalOutputLen }
func (p Params) QueryRandLength() uint   { return 1 + p.EvalOutputLen }

type Valid[
	G Gadget[P, V, E, F],
	P arith.Poly[P, E], V arith.Vec[V, E], E arith.Elt, F arith.Fp[E],
] struct {
	Gadget         G    // Gadget to be evaluated
	NumGadgetCalls uint // Number of times each gadget is called.
	Params
}

func (v *Valid[G, P, V, E, F]) ProveRandLength() uint { return v.Gadget.Arity() }
func (v *Valid[G, P, V, E, F]) ProofLength() uint     { return v.Gadget.Arity() + v.gadgetPolyLen() }
func (v *Valid[G, P, V, E, F]) VerifierLength() uint  { return 1 + 1 + v.Gadget.Arity() }
func (v *Valid[G, P, V, E, F]) gadgetPolyLen() uint {
	p, _ := math.NextPow2(1 + v.NumGadgetCalls)
	return 1 + v.Gadget.Degree()*(p-1)
}

func (v *Valid[G, P, V, E, F]) wrapProve(proveRand V) *ProveGadget[G, P, V, E, F] {
	g := new(ProveGadget[G, P, V, E, F])
	proveRandCur := cursor.New(proveRand)
	wireSeeds := proveRandCur.Next(v.Gadget.Arity())
	g.wrapperGadget = v.wrap(wireSeeds)
	return g
}

func (v *Valid[G, P, V, E, F]) wrapQuery(proof V) *QueryGadget[G, P, V, E, F] {
	g := new(QueryGadget[G, P, V, E, F])
	proofCur := cursor.New(proof)
	wireSeeds := proofCur.Next(v.Gadget.Arity())
	g.wrapperGadget = v.wrap(wireSeeds)
	g.poly = P(proofCur.Next(v.gadgetPolyLen()))
	F(&g.alpha).SetRootOfUnityTwoN(g.log2p)
	F(&g.alphaK).SetOne()
	return g
}

func (v *Valid[G, P, V, E, F]) wrap(wireSeeds V) (g wrapperGadget[G, P, V, E, F]) {
	g.inner = v.Gadget
	g.p, g.log2p = math.NextPow2(1 + v.NumGadgetCalls)
	g.wires = arith.NewVec[V](uint(len(wireSeeds)) * g.p)
	wiresCur := cursor.New(g.wires)
	for i := range wireSeeds {
		wiresCur.Next(g.p)[0] = wireSeeds[i]
	}
	return
}

func RangeCheck(
	g Gadget[fp128.Poly, fp128.Vec, fp128.Fp, *fp128.Fp],
	numCalls uint,
	chunkLen uint, sharesInv *fp128.Fp,
	meas, jointRand fp128.Vec,
) (out fp128.Fp) {
	inputs := arith.NewVec[fp128.Vec](2 * chunkLen)
	var evalOut, rPower fp128.Fp
	for i := range numCalls {
		rPower.SetOne()
		for j := range chunkLen {
			index := i*chunkLen + j
			var measElem fp128.Fp
			if index < uint(len(meas)) {
				measElem = meas[index]
			}

			rPower.MulAssign(&jointRand[i])
			inputs[2*j+0].Mul(&rPower, &measElem)
			inputs[2*j+1].Sub(&measElem, sharesInv)
		}

		g.Eval(&evalOut, inputs)
		out.AddAssign(&evalOut)
	}

	return out
}
