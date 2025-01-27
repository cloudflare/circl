// Package flp provides a Fully-Linear Proof (FLP) system.
package flp

import (
	"errors"

	"github.com/cloudflare/circl/vdaf/prio3/arith"
	"github.com/cloudflare/circl/vdaf/prio3/internal/cursor"
)

// FLP is an instance of a FLP by Boneh et al. Crypto, 2019 paper
// "Zero-Knowledge Proofs on Secret-Shared Data via Fully Linear PCPs",
// https://ia.cr/2019/188
// plus some changes described in VDAF specification.
//
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf-13#section-7.1
type FLP[
	G Gadget[P, V, E, F],
	P arith.Poly[P, E], V arith.Vec[V, E], E arith.Elt, F arith.Fp[E],
] struct {
	// Eval evaluates the arithmetic circuit on a measurement and joint randomness.
	Eval func(out V, g Gadget[P, V, E, F], numCalls uint, meas, jointRand V, numShares uint8)
	Valid[G, P, V, E, F]
}

// Prove returns a proof attesting validity to the given measurement.
// Prove randomness must be provided.
// Some statements may require joint randomness too.
//
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf-13#section-7.3.3
func (f *FLP[G, P, V, E, F]) Prove(meas, proveRand, jointRand V) V {
	proof := arith.NewVec[V](f.ProofLength())
	proofCur := cursor.New(proof)

	g := f.Valid.wrapProve(proveRand)
	out := arith.NewVec[V](f.EvalOutputLength())
	f.Eval(out, g, f.Valid.NumGadgetCalls, meas, jointRand, 1)

	// invN is the inverse of N = g.p.
	// Also, since g.p is always a power of two, we call a faster inversion
	// method that receives the log2 of g.p.
	invN := F(new(E))
	invN.InvTwoN(g.log2p)

	arity := g.Arity()
	wirePoly := make([]P, arity)
	wirePolyN := arith.NewVec[V](arity * g.p)
	wirePolyNCur := cursor.New(wirePolyN)
	wiresCur := cursor.New(g.wires)
	for i := range wirePoly {
		wire := wiresCur.Next(g.p)
		wirePolyI := wirePolyNCur.Next(g.p)
		wirePolyI.InvNTT(wire, g.p)
		// Extracts the constant factor (1/N) to be multiplied after
		// polynomial interpolation.
		wirePolyI.ScalarMul(invN)
		wirePoly[i] = P(wirePolyI)
		proofCur.Next(1)[0] = wire[0]
	}

	gadgetPoly := P(proofCur.Next(f.gadgetPolyLen()))
	g.EvalPoly(gadgetPoly, wirePoly)
	return proof
}

// Query is the linear Query algorithm run by each verifier on a share of the
// measurement and proof.
// Query randomness must be provided.
// Some statements may require joint randomness too.
//
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf-13#section-7.3.4
func (f *FLP[G, P, V, E, F]) Query(
	measShare, proofShare, queryRand, jointRand V, numShares uint8,
) (verifierMsg V, err error) {
	verifierMsg = arith.NewVec[V](f.VerifierLength())
	verifierCur := cursor.New(verifierMsg)
	queryRandCur := cursor.New(queryRand)

	g := f.Valid.wrapQuery(proofShare)
	outLen := f.EvalOutputLength()
	out := arith.NewVec[V](outLen)
	f.Eval(out, g, f.Valid.NumGadgetCalls, measShare, jointRand, numShares)

	v := verifierCur.Next(1)
	if outLen > 1 {
		v[0] = out.DotProduct(queryRandCur.Next(outLen))
	} else {
		v[0] = out[0]
	}

	// Check that t^p != 1. Since p=2^log2p, this requires log2P squares.
	t := &queryRandCur.Next(1)[0]
	tp := F(new(E))
	*tp = *t
	for range g.log2p {
		tp.Sqr(tp)
	}

	if tp.IsOne() {
		return nil, ErrInvalidEval
	}

	// invN is the inverse of N = g.p.
	// Also, since g.p is always a power of two, we call a faster inversion
	// method that receives the log2 of g.p.
	invN := F(new(E))
	invN.InvTwoN(g.log2p)

	wireChecks := verifierCur.Next(g.Arity())
	wirePoly := arith.NewPoly[P](g.p - 1)
	wirei := cursor.New(g.wires)
	for i := range wireChecks {
		V(wirePoly).InvNTT(wirei.Next(g.p), g.p)
		wireChecks[i] = wirePoly.Evaluate(t)
		// Extracts the constant factor (1/N) to be multiplied after
		// polynomial interpolation and evaluation.
		F(&wireChecks[i]).MulAssign(invN)
	}

	gadgetCheck := &verifierCur.Next(1)[0]
	*gadgetCheck = g.poly.Evaluate(t)
	return verifierMsg, nil
}

// Decide returns true if the measurement from which it was generated is valid.
//
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf-13#section-7.3.5
func (f *FLP[G, P, V, E, F]) Decide(verifierMsg V) bool {
	if len(verifierMsg) != int(f.VerifierLength()) {
		return false
	}

	verifierMsgCur := cursor.New(verifierMsg)
	v := F(&verifierMsgCur.Next(1)[0])
	if !v.IsZero() {
		return false
	}

	wireChecks := verifierMsgCur.Next(f.Valid.Gadget.Arity())
	gadgetCheck := &verifierMsgCur.Next(1)[0]
	check := F(new(E))
	f.Valid.Gadget.Eval(check, wireChecks)
	return check.IsEqual(gadgetCheck)
}

var (
	ErrOutputLen        = errors.New("wrong output length")
	ErrMeasurementLen   = errors.New("invalid measurement length")
	ErrMeasurementValue = errors.New("invalid measurement value")
	ErrInvalidEval      = errors.New("invalid evaluation point")
)
