package prio3

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/vdaf/prio3/count"
	"github.com/cloudflare/circl/vdaf/prio3/histogram"
	"github.com/cloudflare/circl/vdaf/prio3/internal/prio3"
	"github.com/cloudflare/circl/vdaf/prio3/mhcv"
	"github.com/cloudflare/circl/vdaf/prio3/sum"
	"github.com/cloudflare/circl/vdaf/prio3/sumvec"
)

type VectorCount struct {
	VectorBase[uint64, uint64]
}

type VectorSum struct {
	VectorBase[uint64, uint64]
	MaxMeas uint64 `json:"max_measurement"`
}

type VectorSumVec struct {
	VectorBase[[]uint64, []uint64]
	Length   uint `json:"length"`
	Bits     uint `json:"bits"`
	ChunkLen uint `json:"chunk_length"`
}

type VectorHistogram struct {
	VectorBase[uint64, []uint64]
	Length   uint `json:"length"`
	ChunkLen uint `json:"chunk_length"`
}

type VectorMultiHotCountVec struct {
	VectorBase[[]bool, []uint64]
	Length    uint `json:"length"`
	MaxWeight uint `json:"max_weight"`
	ChunkLen  uint `json:"chunk_length"`
}

type VectorBase[Measurement, Aggregate any] struct {
	Prep []Prepare[Measurement] `json:"prep"`
	Params[Aggregate]
}

type Params[Aggregate any] struct {
	AggParam  string    `json:"agg_param"`
	AggResult Aggregate `json:"agg_result"`
	AggShares []Hex     `json:"agg_shares"`
	Ctx       Hex       `json:"ctx"`
	VerifyKey Hex       `json:"verify_key"`
	Shares    uint8     `json:"shares"`
}

type Prepare2[Measurement any] struct {
	Measurement Measurement `json:"measurement"`
	PrepareParams
}

type Prepare[Measurement any] struct {
	Measurement Measurement `json:"measurement"`
	PrepareParams
}

type PrepareParams struct {
	InputShares  []Hex   `json:"input_shares"`
	Nonce        Hex     `json:"nonce"`
	OutShares    [][]Hex `json:"out_shares"`
	PrepMessages []Hex   `json:"prep_messages"`
	PrepShares   [][]Hex `json:"prep_shares"`
	PublicShare  Hex     `json:"public_share"`
	Rand         Hex     `json:"rand"`
}

func convert[Aggregate any](
	t testing.TB, in *VectorBase[uint64, Aggregate],
) (out VectorBase[bool, Aggregate]) {
	out.Params = in.Params
	out.Prep = make([]Prepare[bool], len(in.Prep))
	for i := range in.Prep {
		out.Prep[i].PrepareParams = in.Prep[i].PrepareParams
		switch in.Prep[i].Measurement {
		case 0:
			out.Prep[i].Measurement = false
		case 1:
			out.Prep[i].Measurement = true
		default:
			t.Fatal("invalid measurement")
		}
	}

	return
}

func TestVector(t *testing.T) {
	fileNames, err := filepath.Glob("./testdata/Prio3*.json")
	if err != nil {
		t.Fatal(err)
	}

	for _, fileName := range fileNames {
		testName := strings.TrimSuffix(filepath.Base(fileName), ".json")

		t.Run(testName, func(t *testing.T) {
			vdaf := strings.Split(strings.TrimPrefix(testName, "Prio3"), "_")[0]

			switch vdaf {
			case "Count":
				v := readFile[VectorCount](t, fileName)
				c, err := count.New(v.Shares, v.Ctx)
				test.CheckNoErr(t, err, "new Count failed")
				runPrio3(t, c, convert(t, &v.VectorBase))

			case "Sum":
				v := readFile[VectorSum](t, fileName)
				s, err := sum.New(v.Shares, v.MaxMeas, v.Ctx)
				test.CheckNoErr(t, err, "new Sum failed")
				runPrio3(t, s, v.VectorBase)

			case "SumVec":
				v := readFile[VectorSumVec](t, fileName)
				s, err := sumvec.New(
					v.Shares, v.Length, v.Bits, v.ChunkLen, v.Ctx)
				test.CheckNoErr(t, err, "new SumVec failed")
				runPrio3(t, s, v.VectorBase)

			case "Histogram":
				v := readFile[VectorHistogram](t, fileName)
				h, err := histogram.New(v.Shares, v.Length, v.ChunkLen, v.Ctx)
				test.CheckNoErr(t, err, "new Histogram failed")
				runPrio3(t, h, v.VectorBase)

			case "MultihotCountVec":
				v := readFile[VectorMultiHotCountVec](t, fileName)
				m, err := mhcv.New(
					v.Shares, v.Length, v.MaxWeight, v.ChunkLen, v.Ctx)
				test.CheckNoErr(t, err, "new MultiHotCountVec failed")
				runPrio3(t, m, v.VectorBase)

			default:
				t.Fatal("unexpected test v for " + vdaf)
			}
		})
	}
}

func runPrio3[
	P Prio3[
		Measurement, Aggregate,
		AggShare, InputShare, OutShare, PrepShare, PrepState,
	],
	Measurement, Aggregate any,
	AggShare, InputShare, OutShare, PrepShare, PrepState any,
](t *testing.T, p P, v VectorBase[Measurement, Aggregate]) {
	params := p.Params()
	shares := params.Shares()
	verifyKey := prio3.VerifyKey(v.VerifyKey)

	aggShares := make([]AggShare, shares)
	for i := range aggShares {
		aggShares[i] = p.AggregationInit()
	}

	for _, instance := range v.Prep {
		nonce := prio3.Nonce(instance.Nonce)
		randb := instance.Rand
		meas := instance.Measurement

		pubShare, inputShares, err := p.Shard(meas, &nonce, randb)
		test.CheckNoErr(t, err, "shard failed")
		checkEqual(t, &pubShare, instance.PublicShare)
		for i := range inputShares {
			checkEqual(t, &inputShares[i], instance.InputShares[i])
		}

		var prepStates []*PrepState
		var outboundPrepShares []PrepShare
		for i := range shares {
			state, share, errx := p.PrepInit(
				&verifyKey, &nonce, i, pubShare, inputShares[i])
			test.CheckNoErr(t, errx, "prepare init failed")

			prepStates = append(prepStates, state)
			outboundPrepShares = append(outboundPrepShares, *share)
		}

		for i := range outboundPrepShares {
			checkEqual(t, &outboundPrepShares[i], instance.PrepShares[0][i])
		}

		prepMsg, err := p.PrepSharesToPrep(outboundPrepShares)
		test.CheckNoErr(t, err, "PrepSharesToPrep failed")
		checkEqual(t, prepMsg, instance.PrepMessages[0])

		for i := range shares {
			outShare, err := p.PrepNext(prepStates[i], prepMsg)
			test.CheckNoErr(t, err, "PrepNext failed")
			checkEqual(t, outShare, slices.Concat(instance.OutShares[i]...))

			p.AggregationUpdate(&aggShares[i], outShare)
		}
	}

	numMeas := uint(len(v.Prep))
	aggResult, err := p.Unshard(aggShares, numMeas)
	test.CheckNoErr(t, err, "unshard failed")

	got := *aggResult
	want := v.AggResult
	if !isEqual(t, got, want) {
		test.ReportError(t, got, want)
	}
}
