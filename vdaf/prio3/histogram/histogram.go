// Package histogram is a VDAF for aggregating integer measurements into buckets.
package histogram

import (
	"github.com/cloudflare/circl/vdaf/prio3/arith"
	"github.com/cloudflare/circl/vdaf/prio3/arith/fp128"
	"github.com/cloudflare/circl/vdaf/prio3/internal/flp"
	"github.com/cloudflare/circl/vdaf/prio3/internal/prio3"
)

type (
	poly        = fp128.Poly
	Vec         = fp128.Vec
	Fp          = fp128.Fp
	AggShare    = prio3.AggShare[Vec, Fp]
	InputShare  = prio3.InputShare[Vec, Fp]
	Nonce       = prio3.Nonce
	OutShare    = prio3.OutShare[Vec, Fp]
	PrepMessage = prio3.PrepMessage
	PrepShare   = prio3.PrepShare[Vec, Fp]
	PrepState   = prio3.PrepState[Vec, Fp]
	PublicShare = prio3.PublicShare
	VerifyKey   = prio3.VerifyKey
)

// Histogram is a verifiable distributed aggregation function in which each
// measurement increments by one the histogram bucket, out of a set of fixed
// buckets, and the aggregate result counts the number of measurements in each
// bucket.
type Histogram struct {
	p prio3.Prio3[uint64, []uint64, *flpHistogram, Vec, Fp, *Fp]
}

func New(numShares uint8, length, chunkLen uint, context []byte) (h *Histogram, err error) {
	const histogramID = 4
	h = new(Histogram)
	h.p, err = prio3.New(newFlpHistogram(length, chunkLen), histogramID, numShares, context)
	if err != nil {
		return nil, err
	}

	return h, nil
}

func (h *Histogram) Params() prio3.Params { return h.p.Params() }

func (h *Histogram) Shard(measurement uint64, nonce *Nonce, rand []byte,
) (PublicShare, []InputShare, error) {
	return h.p.Shard(measurement, nonce, rand)
}

func (h *Histogram) PrepInit(
	verifyKey *VerifyKey,
	nonce *Nonce,
	aggID uint8,
	publicShare PublicShare,
	inputShare InputShare,
) (*PrepState, *PrepShare, error) {
	return h.p.PrepInit(verifyKey, nonce, aggID, publicShare, inputShare)
}

func (h *Histogram) PrepSharesToPrep(prepShares []PrepShare) (*PrepMessage, error) {
	return h.p.PrepSharesToPrep(prepShares)
}

func (h *Histogram) PrepNext(state *PrepState, msg *PrepMessage) (*OutShare, error) {
	return h.p.PrepNext(state, msg)
}

func (h *Histogram) AggregateInit() AggShare { return h.p.AggregateInit() }

func (h *Histogram) AggregateUpdate(aggShare *AggShare, outShare *OutShare) {
	h.p.AggregateUpdate(aggShare, outShare)
}

func (h *Histogram) Unshard(aggShares []AggShare, numMeas uint) (aggregate *[]uint64, err error) {
	return h.p.Unshard(aggShares, numMeas)
}

type flpHistogram struct {
	flp.FLP[flp.GadgetParallelSumInnerMul, poly, Vec, Fp, *Fp]
	length   uint
	chunkLen uint
}

func newFlpHistogram(length, chunkLen uint) *flpHistogram {
	h := new(flpHistogram)
	numGadgetCalls := (length + chunkLen - 1) / chunkLen
	h.length = length
	h.chunkLen = chunkLen
	h.Valid.MeasurementLen = length
	h.Valid.JointRandLen = numGadgetCalls
	h.Valid.OutputLen = length
	h.Valid.EvalOutputLen = 2
	h.Gadget = flp.GadgetParallelSumInnerMul{Count: chunkLen}
	h.NumGadgetCalls = numGadgetCalls
	h.FLP.Eval = h.Eval
	return h
}

func (h *flpHistogram) Eval(
	out Vec, g flp.Gadget[poly, Vec, Fp, *Fp], numCalls uint,
	meas, jointRand Vec, numShares uint8,
) {
	var invShares Fp
	invShares.InvUint64(uint64(numShares))
	out[0] = flp.RangeCheck(g, numCalls, h.chunkLen, &invShares, meas, jointRand)

	sumCheck := &out[1]
	sumCheck.SubAssign(&invShares)
	for i := range meas {
		sumCheck.AddAssign(&meas[i])
	}
}

func (h *flpHistogram) Encode(measurement uint64) (out Vec, err error) {
	if measurement > uint64(h.length) {
		return nil, flp.ErrMeasurementValue
	}

	out = arith.NewVec[Vec](h.Valid.MeasurementLen)
	out[measurement].SetOne()

	return
}

func (h *flpHistogram) Truncate(meas Vec) Vec { return meas }

func (h *flpHistogram) Decode(output Vec, numMeas uint) (*[]uint64, error) {
	if len(output) < int(h.Valid.OutputLen) {
		return nil, flp.ErrOutputLen
	}

	var err error
	out := make([]uint64, len(output))
	for i := range output {
		out[i], err = output[i].GetUint64()
		if err != nil {
			return nil, err
		}
	}

	return &out, nil
}
