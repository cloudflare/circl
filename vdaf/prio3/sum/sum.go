// Package sum is a VDAF for aggregating integers in a pre-determined range.
package sum

import (
	"math/bits"

	"github.com/cloudflare/circl/vdaf/prio3/arith/fp64"
	"github.com/cloudflare/circl/vdaf/prio3/internal/cursor"
	"github.com/cloudflare/circl/vdaf/prio3/internal/flp"
	"github.com/cloudflare/circl/vdaf/prio3/internal/prio3"
)

type (
	poly        = fp64.Poly
	Vec         = fp64.Vec
	Fp          = fp64.Fp
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

// Sum is a verifiable distributed aggregation function in which each
// measurement is an integer in the range [0, maxMeasurement], where
// maxMeasurement defines the largest valid measurement, the aggregated result
// is the sum of all the measurements.
type Sum struct {
	p prio3.Prio3[uint64, uint64, *flpSum, Vec, Fp, *Fp]
}

func New(numShares uint8, maxMeasurement uint64, context []byte) (s *Sum, err error) {
	const sumID = 2
	s = new(Sum)
	s.p, err = prio3.New(newFlpSum(maxMeasurement), sumID, numShares, context)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Sum) Params() prio3.Params { return s.p.Params() }

func (s *Sum) Shard(measurement uint64, nonce *Nonce, rand []byte,
) (PublicShare, []InputShare, error) {
	return s.p.Shard(measurement, nonce, rand)
}

func (s *Sum) PrepInit(
	verifyKey *VerifyKey,
	nonce *Nonce,
	aggID uint8,
	publicShare PublicShare,
	inputShare InputShare,
) (*PrepState, *PrepShare, error) {
	return s.p.PrepInit(verifyKey, nonce, aggID, publicShare, inputShare)
}

func (s *Sum) PrepSharesToPrep(prepShares []PrepShare) (*PrepMessage, error) {
	return s.p.PrepSharesToPrep(prepShares)
}

func (s *Sum) PrepNext(state *PrepState, msg *PrepMessage) (*OutShare, error) {
	return s.p.PrepNext(state, msg)
}

func (s *Sum) AggregateInit() AggShare { return s.p.AggregateInit() }

func (s *Sum) AggregateUpdate(aggShare *AggShare, outShare *OutShare) {
	s.p.AggregateUpdate(aggShare, outShare)
}

func (s *Sum) Unshard(aggShares []AggShare, numMeas uint) (aggregate *uint64, err error) {
	return s.p.Unshard(aggShares, numMeas)
}

type flpSum struct {
	flp.FLP[flp.GadgetPolyEvalx2x, poly, Vec, Fp, *Fp]
	bits   uint
	offset Fp
}

func newFlpSum(maxMeasurement uint64) *flpSum {
	s := new(flpSum)
	bits := uint(bits.Len64(maxMeasurement))
	offset := (uint64(1) << uint64(bits)) - 1 - maxMeasurement

	s.bits = bits
	err := s.offset.SetUint64(offset)
	if err != nil {
		panic(err)
	}

	s.Valid.MeasurementLen = 2 * bits
	s.Valid.JointRandLen = 0
	s.Valid.OutputLen = 1
	s.Valid.EvalOutputLen = 2*bits + 1
	s.Gadget = flp.GadgetPolyEvalx2x{}
	s.NumGadgetCalls = 2 * bits
	s.FLP.Eval = s.Eval
	return s
}

func (s *flpSum) EvalEval(
	out Vec, g flp.Gadget[poly, Vec, Fp, *Fp], numCalls uint,
	meas, jointRand Vec, numShares uint8,
) {
	var input [1]Fp
	for i := range meas {
		input[0] = meas[i]
		g.Eval(&out[i], input[:])
	}

	measCur := cursor.New(meas)
	a := measCur.Next(s.bits).JoinBits()
	b := measCur.Next(s.bits).JoinBits()

	var invShares Fp
	invShares.InvUint64(uint64(numShares))
	rangeCheck := &out[len(meas)]
	rangeCheck.Mul(&s.offset, &invShares)
	rangeCheck.AddAssign(&a)
	rangeCheck.SubAssign(&b)
}

func (s *flpSum) Encode(measurement uint64) (Vec, error) {
	offset, err := s.offset.GetUint64()
	if err != nil {
		return nil, err
	}

	out := make(Vec, s.Valid.MeasurementLen)
	outCur := cursor.New(out)
	err = outCur.Next(s.bits).SplitBits(measurement)
	if err != nil {
		return nil, err
	}

	err = outCur.Next(s.bits).SplitBits(measurement + offset)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (s *flpSum) Truncate(meas Vec) Vec {
	return Vec{meas[:s.bits].JoinBits()}
}

func (s *flpSum) Decode(output Vec, numMeas uint) (*uint64, error) {
	if len(output) < int(s.Valid.OutputLen) {
		return nil, flp.ErrOutputLen
	}

	n, err := output[0].GetUint64()
	if err != nil {
		return nil, err
	}

	return &n, nil
}
