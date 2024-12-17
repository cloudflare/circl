// Package mhcv is a VDAF for aggregating bounded vectors of Booleans into buckets.
package mhcv

import (
	"math/big"
	"math/bits"

	"github.com/cloudflare/circl/vdaf/prio3/arith"
	"github.com/cloudflare/circl/vdaf/prio3/arith/fp128"
	"github.com/cloudflare/circl/vdaf/prio3/internal/cursor"
	"github.com/cloudflare/circl/vdaf/prio3/internal/flp"
	"github.com/cloudflare/circl/vdaf/prio3/internal/prio3"
)

type (
	poly       = fp128.Poly
	Vec        = fp128.Vec
	Fp         = fp128.Fp
	AggShare   = prio3.AggShare[Vec, Fp]
	InputShare = prio3.InputShare[Vec, Fp]
	OutShare   = prio3.OutShare[Vec, Fp]
	PrepShare  = prio3.PrepShare[Vec, Fp]
	PrepState  = prio3.PrepState[Vec, Fp]
)

// MultiHotCountVec is a verifiable distributed aggregation function in which
// each measurement is a vector of Boolean values, where the number of True
// values is bounded.
// This provides a functionality similar to Histogram except that more than
// one entry (or none at all) may be non-zero.
type MultiHotCountVec struct {
	p prio3.Prio3[[]bool, []uint64, *flpMultiHotCountVec, Vec, Fp, *Fp]
}

func New(numShares uint8, length, maxWeight, chunkLen uint, context []byte) (m *MultiHotCountVec, err error) {
	const multihotCountVecID uint8 = 5
	m = new(MultiHotCountVec)
	m.p, err = prio3.New(
		newFlpMultiCountHotVec(length, maxWeight, chunkLen),
		multihotCountVecID, numShares, context)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (m *MultiHotCountVec) Params() prio3.Params { return m.p.Params() }

func (m *MultiHotCountVec) Shard(measurement []bool, nonce *prio3.Nonce, rand []byte,
) (prio3.PublicShare, []InputShare, error) {
	return m.p.Shard(measurement, nonce, rand)
}

func (m *MultiHotCountVec) PrepInit(
	verifyKey *prio3.VerifyKey,
	nonce *prio3.Nonce,
	aggID uint8,
	publicShare prio3.PublicShare,
	inputShare InputShare,
) (*PrepState, *PrepShare, error) {
	return m.p.PrepInit(verifyKey, nonce, aggID, publicShare, inputShare)
}

func (m *MultiHotCountVec) PrepSharesToPrep(prepShares []PrepShare) (*prio3.PrepMessage, error) {
	return m.p.PrepSharesToPrep(prepShares)
}

func (m *MultiHotCountVec) PrepNext(state *PrepState, msg *prio3.PrepMessage) (*OutShare, error) {
	return m.p.PrepNext(state, msg)
}

func (m *MultiHotCountVec) AggregationInit() AggShare { return m.p.AggregationInit() }

func (m *MultiHotCountVec) AggregationUpdate(aggShare *AggShare, outShare *OutShare) {
	m.p.AggregationUpdate(aggShare, outShare)
}

func (m *MultiHotCountVec) Unshard(aggShares []AggShare, numMeas uint) (aggregate *[]uint64, err error) {
	return m.p.Unshard(aggShares, numMeas)
}

type flpMultiHotCountVec struct {
	flp.FLP[flp.GadgetParallelSum, poly, Vec, Fp, *Fp]
	bits     uint
	chunkLen uint
	length   uint
	offset   Fp
}

func newFlpMultiCountHotVec(length, maxWeight, chunkLen uint) *flpMultiHotCountVec {
	m := new(flpMultiHotCountVec)
	if length == 0 {
		panic("length cannot be zero")
	}
	if maxWeight > length {
		panic("maxWeight cannot be greater than length")
	}
	if chunkLen == 0 {
		panic("chunkLen cannot be zero")
	}

	bits := uint(bits.Len64(uint64(maxWeight)))
	offset := (uint64(1) << uint64(bits)) - 1 - uint64(maxWeight)

	b := new(big.Int).SetBytes(new(Fp).Order())
	b.Sub(b, big.NewInt(int64(offset)))
	if b.Cmp(big.NewInt(int64(length))) <= 0 {
		panic("length and maxWeight are too large for the current field size")
	}

	numCalls := (length + bits + chunkLen - 1) / chunkLen

	m.bits = bits
	m.length = length
	m.chunkLen = chunkLen
	err := m.offset.SetUint64(offset)
	if err != nil {
		panic(err)
	}

	m.Valid.MeasurementLen = length + bits
	m.Valid.JointRandLen = numCalls
	m.Valid.OutputLen = length
	m.Valid.EvalOutputLen = 2
	m.Gadget = flp.GadgetParallelSum{Count: chunkLen}
	m.NumCalls = numCalls
	m.FLP.Eval = m.Eval
	return m
}

func (m *flpMultiHotCountVec) Eval(out Vec, g flp.Gadget[poly, Vec, Fp, *Fp], numCalls uint, meas, jointRand Vec, shares uint8) {
	var invShares Fp
	invShares.InvUint64(uint64(shares))
	out[0] = flp.RangeCheck(g, numCalls, m.chunkLen, &invShares, meas, jointRand)

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
