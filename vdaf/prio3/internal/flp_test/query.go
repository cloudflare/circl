package flp_test

import (
	"errors"
	"testing"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/math"
	"github.com/cloudflare/circl/vdaf/prio3/arith"
	"github.com/cloudflare/circl/vdaf/prio3/internal/flp"
)

func TestInvalidQuery[
	G flp.Gadget[P, V, E, F],
	P arith.Poly[P, E], V arith.Vec[V, E], E arith.Elt, F arith.Fp[E],
](t *testing.T, f *flp.FLP[G, P, V, E, F]) {
	const NumShares = 2
	measShare := arith.NewVec[V](f.MeasurementLength())
	proofShare := arith.NewVec[V](f.ProofLength())
	queryRand := arith.NewVec[V](f.QueryRandLength())
	jointRand := arith.NewVec[V](f.JointRandLength())

	s := sha3.NewShake128()
	test.CheckNoErr(t, measShare.Random(&s), "measShare random failed")
	test.CheckNoErr(t, proofShare.Random(&s), "proofShare random failed")
	test.CheckNoErr(t, queryRand.Random(&s), "queryRand random failed")
	test.CheckNoErr(t, jointRand.Random(&s), "jointRand random failed")

	var index uint
	if f.EvalOutputLength() > 1 {
		index = f.EvalOutputLength()
	}

	invalidEvaluationPoint := F(&queryRand[index])
	_, logP := math.NextPow2(1 + f.Valid.NumGadgetCalls)
	root := F(new(E))
	// Check all subgroups of order 2^logN <= 2^logP.
	for logN := range logP + 1 {
		root.SetRootOfUnityTwoN(logN)
		invalidEvaluationPoint.SetOne()
		// Check every element in the subgroup of order 2^logN.
		for range 1 << logN {
			_, err := f.Query(measShare, proofShare, queryRand, jointRand, NumShares)
			if !errors.Is(err, flp.ErrInvalidEval) {
				test.ReportError(t, err, flp.ErrInvalidEval)
			}

			invalidEvaluationPoint.MulAssign(root)
		}
	}
}
