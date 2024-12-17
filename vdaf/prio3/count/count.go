// Package count is a VDAF for counting boolean measurements.
package count

import (
	"github.com/cloudflare/circl/vdaf/prio3/arith"
	"github.com/cloudflare/circl/vdaf/prio3/arith/fp64"
	"github.com/cloudflare/circl/vdaf/prio3/internal/flp"
	"github.com/cloudflare/circl/vdaf/prio3/internal/prio3"
)

type (
	poly       = fp64.Poly
	Vec        = fp64.Vec
	Fp         = fp64.Fp
	AggShare   = prio3.AggShare[Vec, Fp]
	InputShare = prio3.InputShare[Vec, Fp]
	OutShare   = prio3.OutShare[Vec, Fp]
	PrepShare  = prio3.PrepShare[Vec, Fp]
	PrepState  = prio3.PrepState[Vec, Fp]
)

// Count is a verifiable distributed aggregation function in which each
// measurement is either one or zero and the aggregate result is the sum of
// the measurements.
type Count struct {
	p prio3.Prio3[bool, uint64, *flpCount, Vec, Fp, *Fp]
}

func New(numShares uint8, context []byte) (c *Count, err error) {
	const countID uint8 = 1
	c = new(Count)
	c.p, err = prio3.New(newFlpCount(), countID, numShares, context)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Count) Params() prio3.Params { return c.p.Params() }

func (c *Count) Shard(measurement bool, nonce *prio3.Nonce, rand []byte,
) (prio3.PublicShare, []InputShare, error) {
	return c.p.Shard(measurement, nonce, rand)
}

func (c *Count) PrepInit(
	verifyKey *prio3.VerifyKey,
	nonce *prio3.Nonce,
	aggID uint8,
	publicShare prio3.PublicShare,
	inputShare InputShare,
) (*PrepState, *PrepShare, error) {
	return c.p.PrepInit(verifyKey, nonce, aggID, publicShare, inputShare)
}

func (c *Count) PrepSharesToPrep(prepShares []PrepShare) (*prio3.PrepMessage, error) {
	return c.p.PrepSharesToPrep(prepShares)
}

func (c *Count) PrepNext(state *PrepState, msg *prio3.PrepMessage) (*OutShare, error) {
	return c.p.PrepNext(state, msg)
}

func (c *Count) AggregationInit() AggShare { return c.p.AggregationInit() }

func (c *Count) AggregationUpdate(aggShare *AggShare, outShare *OutShare) {
	c.p.AggregationUpdate(aggShare, outShare)
}

func (c *Count) Unshard(aggShares []AggShare, numMeas uint) (aggregate *uint64, err error) {
	return c.p.Unshard(aggShares, numMeas)
}

type flpCount struct {
	flp.FLP[flp.GadgetMulFp64, poly, Vec, Fp, *Fp]
}

func newFlpCount() *flpCount {
	c := new(flpCount)
	c.Valid.MeasurementLen = 1
	c.Valid.JointRandLen = 0
	c.Valid.OutputLen = 1
	c.Valid.EvalOutputLen = 1
	c.Gadget = flp.GadgetMulFp64{}
	c.NumCalls = 1
	c.FLP.Eval = c.Eval
	return c
}

func (c *flpCount) Eval(
	out Vec, g flp.Gadget[poly, Vec, Fp, *Fp], _numCalls uint,
	meas, _jointRand Vec, _shares uint8,
) {
	g.Eval(&out[0], Vec{meas[0], meas[0]})
	out[0].SubAssign(&meas[0])
}

func (c *flpCount) Encode(measurement bool) (Vec, error) {
	out := arith.NewVec[Vec](1)
	if measurement {
		out[0].SetOne()
	}

	return out, nil
}

func (c *flpCount) Truncate(meas Vec) Vec { return meas }

func (c *flpCount) Decode(output Vec, numMeas uint) (*uint64, error) {
	if len(output) < int(c.Valid.OutputLen) {
		return nil, flp.ErrOutputLen
	}

	n, err := output[0].GetUint64()
	if err != nil {
		return nil, err
	}

	return &n, nil
}
