// Package mhcv is a VDAF for aggregating vectors of Booleans with bounded weight.
package mhcv

import (
	"errors"
	"math/big"
	"math/bits"

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

// MultiHotCountVec is a verifiable distributed aggregation function in which
// each measurement is a vector of Booleans, where the number of True
// values is bounded.
// This provides a functionality similar to Histogram except that more than
// one entry (or none at all) may be non-zero.
type MultiHotCountVec struct {
	p prio3.Prio3[[]bool, []uint64, *flpMultiHotCountVec, Vec, Fp, *Fp]
}

func New(numShares uint8, length, maxWeight, chunkLength uint, context []byte) (m *MultiHotCountVec, err error) {
	const multihotCountVecID = 5
	flp, err := newFlpMultiCountHotVec(length, maxWeight, chunkLength)
	if err != nil {
		return nil, err
	}

	m = new(MultiHotCountVec)
	m.p, err = prio3.New(flp, multihotCountVecID, numShares, context)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (m *MultiHotCountVec) Params() prio3.Params { return m.p.Params() }

func (m *MultiHotCountVec) Shard(measurement []bool, nonce *Nonce, rand []byte,
) (PublicShare, []InputShare, error) {
	return m.p.Shard(measurement, nonce, rand)
}

func (m *MultiHotCountVec) PrepInit(
	verifyKey *VerifyKey,
	nonce *Nonce,
	aggID uint8,
	publicShare PublicShare,
	inputShare InputShare,
) (*PrepState, *PrepShare, error) {
	return m.p.PrepInit(verifyKey, nonce, aggID, publicShare, inputShare)
}

func (m *MultiHotCountVec) PrepSharesToPrep(prepShares []PrepShare) (*PrepMessage, error) {
	return m.p.PrepSharesToPrep(prepShares)
}

func (m *MultiHotCountVec) PrepNext(state *PrepState, msg *PrepMessage) (*OutShare, error) {
	return m.p.PrepNext(state, msg)
}

func (m *MultiHotCountVec) AggregateInit() AggShare { return m.p.AggregateInit() }

func (m *MultiHotCountVec) AggregateUpdate(aggShare *AggShare, outShare *OutShare) {
	m.p.AggregateUpdate(aggShare, outShare)
}

func (m *MultiHotCountVec) Unshard(aggShares []AggShare, numMeas uint) (aggregate *[]uint64, err error) {
	return m.p.Unshard(aggShares, numMeas)
}

type flpMultiHotCountVec struct {
	flp.FLP[flp.GadgetParallelSumInnerMul, poly, Vec, Fp, *Fp]
	bits        uint
	chunkLength uint
	length      uint
	offset      Fp
}

func newFlpMultiCountHotVec(length, maxWeight, chunkLength uint) (*flpMultiHotCountVec, error) {
	if length == 0 {
		return nil, ErrLength
	}
	if maxWeight > length {
		return nil, ErrMaxWeight
	}
	if chunkLength == 0 {
		return nil, ErrChunkLength
	}

	bits := uint(bits.Len64(uint64(maxWeight)))
	offset := (uint64(1) << uint64(bits)) - 1 - uint64(maxWeight)

	b := new(big.Int).SetBytes(new(Fp).Order())
	b.Sub(b, big.NewInt(int64(offset)))
	if b.Cmp(big.NewInt(int64(length))) <= 0 {
		return nil, ErrFieldSize
	}

	numGadgetCalls := (length + bits + chunkLength - 1) / chunkLength

	m := new(flpMultiHotCountVec)
	m.bits = bits
	m.length = length
	m.chunkLength = chunkLength
	err := m.offset.SetUint64(offset)
	if err != nil {
		return nil, err
	}

	m.Valid.MeasurementLen = length + bits
	m.Valid.JointRandLen = numGadgetCalls
	m.Valid.OutputLen = length
	m.Valid.EvalOutputLen = 2
	m.Gadget = flp.GadgetParallelSumInnerMul{Count: chunkLength}
	m.NumGadgetCalls = numGadgetCalls
	m.FLP.Eval = m.Eval
	return m, nil
}

func (m *flpMultiHotCountVec) Eval(
	out Vec, g flp.Gadget[poly, Vec, Fp, *Fp], numCalls uint,
	meas, jointRand Vec, numShares uint8,
) {
	var invShares Fp
	invShares.InvUint64(uint64(numShares))
	out[0] = flp.RangeCheck(g, numCalls, m.chunkLength, &invShares, meas, jointRand)

	measCur := cursor.New(meas)
	countVec := measCur.Next(m.length)
	var weight Fp
	for i := range countVec {
		weight.AddAssign(&countVec[i])
	}

	weightReported := measCur.Next(m.bits).JoinBits()
	weightCheck := &out[1]
	weightCheck.Mul(&m.offset, &invShares)
	weightCheck.AddAssign(&weight)
	weightCheck.SubAssign(&weightReported)
}

func (m *flpMultiHotCountVec) Encode(measurement []bool) (out Vec, err error) {
	n := m.length
	if n != uint(len(measurement)) {
		return nil, flp.ErrMeasurementLen
	}

	out = arith.NewVec[Vec](m.Valid.MeasurementLen)
	outCur := cursor.New(out)
	first := outCur.Next(n)
	weight := uint64(0)
	for i := range measurement {
		if measurement[i] {
			first[i].SetOne()
			weight++
		}
	}

	offset, err := m.offset.GetUint64()
	if err != nil {
		return nil, err
	}

	err = outCur.Next(m.bits).SplitBits(offset + weight)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (m *flpMultiHotCountVec) Truncate(meas Vec) Vec {
	return meas[:m.length]
}

func (m *flpMultiHotCountVec) Decode(output Vec, numMeas uint) (*[]uint64, error) {
	if len(output) < int(m.Valid.OutputLen) {
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

var (
	ErrLength      = errors.New("length cannot be zero")
	ErrMaxWeight   = errors.New("maxWeight cannot be greater than length")
	ErrChunkLength = errors.New("chunkLength cannot be zero")
	ErrFieldSize   = errors.New("length and maxWeight are too large for the current field size")
)
