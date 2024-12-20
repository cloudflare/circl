// Package sumvec is a VDAF for aggregating vectors of integers in a pre-determined range.
package sumvec

import (
	"errors"

	"github.com/cloudflare/circl/vdaf/prio3/arith"
	"github.com/cloudflare/circl/vdaf/prio3/arith/fp128"
	"github.com/cloudflare/circl/vdaf/prio3/internal/cursor"
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

// SumVec is a verifiable distributed aggregation function in which each
// measurement is a fixed-length vector of integers in the range [0, 2^bits).
// the aggregated result is the sum of all the vectors.
type SumVec struct {
	p prio3.Prio3[[]uint64, []uint64, *flpSumVec, Vec, Fp, *Fp]
}

func New(numShares uint8, length, bits, chunkLength uint, context []byte) (s *SumVec, err error) {
	const sumVecID = 3
	flp, err := newFlpSumVec(length, bits, chunkLength)
	if err != nil {
		return nil, err
	}

	s = new(SumVec)
	s.p, err = prio3.New(flp, sumVecID, numShares, context)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *SumVec) Params() prio3.Params { return s.p.Params() }

func (s *SumVec) Shard(measurement []uint64, nonce *Nonce, rand []byte,
) (PublicShare, []InputShare, error) {
	return s.p.Shard(measurement, nonce, rand)
}

func (s *SumVec) PrepInit(
	verifyKey *VerifyKey,
	nonce *Nonce,
	aggID uint8,
	publicShare PublicShare,
	inputShare InputShare,
) (*PrepState, *PrepShare, error) {
	return s.p.PrepInit(verifyKey, nonce, aggID, publicShare, inputShare)
}

func (s *SumVec) PrepSharesToPrep(prepShares []PrepShare) (*PrepMessage, error) {
	return s.p.PrepSharesToPrep(prepShares)
}

func (s *SumVec) PrepNext(state *PrepState, msg *PrepMessage) (*OutShare, error) {
	return s.p.PrepNext(state, msg)
}

func (s *SumVec) AggregateInit() AggShare { return s.p.AggregateInit() }

func (s *SumVec) AggregateUpdate(aggShare *AggShare, outShare *OutShare) {
	s.p.AggregateUpdate(aggShare, outShare)
}

func (s *SumVec) Unshard(aggShares []AggShare, numMeas uint) (aggregate *[]uint64, err error) {
	return s.p.Unshard(aggShares, numMeas)
}

type flpSumVec struct {
	flp.FLP[flp.GadgetParallelSumInnerMul, poly, Vec, Fp, *Fp]
	length   uint
	bits     uint
	chunkLen uint
}

func newFlpSumVec(length, bits, chunkLen uint) (*flpSumVec, error) {
	if bits > 64 {
		return nil, ErrBits
	}

	numGadgetCalls := (length*bits + chunkLen - 1) / chunkLen

	s := new(flpSumVec)
	s.length = length
	s.bits = bits
	s.chunkLen = chunkLen
	s.Valid.MeasurementLen = length * bits
	s.Valid.JointRandLen = numGadgetCalls
	s.Valid.OutputLen = length
	s.Valid.EvalOutputLen = 1
	s.Gadget = flp.GadgetParallelSumInnerMul{Count: chunkLen}
	s.NumGadgetCalls = numGadgetCalls
	s.FLP.Eval = s.Eval
	return s, nil
}

func (s *flpSumVec) Eval(
	out Vec, g flp.Gadget[poly, Vec, Fp, *Fp], numCalls uint,
	meas, jointRand Vec, numShares uint8,
) {
	var invShares Fp
	invShares.InvUint64(uint64(numShares))
	out[0] = flp.RangeCheck(g, numCalls, s.chunkLen, &invShares, meas, jointRand)
}

func (s *flpSumVec) Encode(measurement []uint64) (out Vec, err error) {
	if len(measurement) != int(s.length) {
		return nil, flp.ErrMeasurementLen
	}

	out = make(Vec, s.Valid.MeasurementLen)
	outCur := cursor.New(out)
	for i := range measurement {
		err = outCur.Next(s.bits).SplitBits(measurement[i])
		if err != nil {
			return nil, err
		}
	}

	return
}

func (s *flpSumVec) Truncate(meas Vec) (out Vec) {
	out = arith.NewVec[Vec](s.length)
	measCur := cursor.New(meas)
	for i := range out {
		out[i] = measCur.Next(s.bits).JoinBits()
	}

	return
}

func (s *flpSumVec) Decode(output Vec, numMeas uint) (*[]uint64, error) {
	if len(output) < int(s.Valid.OutputLen) {
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

var ErrBits = errors.New("bits larger than 64 is not supported")
