package prio3

import (
	"crypto/rand"
	"io"
	"slices"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/vdaf/prio3/count"
	"github.com/cloudflare/circl/vdaf/prio3/histogram"
	"github.com/cloudflare/circl/vdaf/prio3/internal/prio3"
	"github.com/cloudflare/circl/vdaf/prio3/mhcv"
	"github.com/cloudflare/circl/vdaf/prio3/sum"
	"github.com/cloudflare/circl/vdaf/prio3/sumvec"
)

type Prio3[
	Measurement, Aggregate any,
	AggShare, InputShare, Nonce, OutShare, PrepMessage, PrepShare, PrepState,
	PublicShare, VerifyKey any,
] interface {
	Params() prio3.Params
	Shard(Measurement, *Nonce, []byte) (PublicShare, []InputShare, error)
	PrepInit(
		*VerifyKey, *Nonce, uint8, PublicShare, InputShare,
	) (*PrepState, *PrepShare, error)
	PrepSharesToPrep([]PrepShare) (*PrepMessage, error)
	PrepNext(*PrepState, *PrepMessage) (*OutShare, error)
	AggregateInit() AggShare
	AggregateUpdate(*AggShare, *OutShare)
	Unshard([]AggShare, uint) (*Aggregate, error)
}

const NumShares = 2

var Context = []byte("TestingPrio3")

func TestCount(t *testing.T) {
	input := []bool{true, true, false}
	want := uint64(2) // Hamming weight of binary inputs.
	c, err := count.New(NumShares, Context)
	test.CheckNoErr(t, err, "new count failed")
	got := testPrio3(t, c, input)
	test.CheckOk(got != nil, "prio3 count failed", t)
	if *got != want {
		test.ReportError(t, *got, want)
	}
}

func TestSum(t *testing.T) {
	const MaxMeas = 4
	input := []uint64{1, 2, 3}
	want := uint64(6) // Sum of each input.
	s, err := sum.New(NumShares, MaxMeas, Context)
	test.CheckNoErr(t, err, "new sum failed")
	got := testPrio3(t, s, input)
	test.CheckOk(got != nil, "prio3 sum failed", t)
	if *got != want {
		test.ReportError(t, *got, want)
	}
}

func TestSumVec(t *testing.T) {
	input := [][]uint64{
		{1, 2, 3, 0},
		{1, 4, 6, 1},
		{1, 6, 9, 2},
	}
	want := []uint64{3, 12, 18, 3} // Element-wise sum of input vectors.
	s, err := sumvec.New(NumShares, 4, 4, 3, Context)
	test.CheckNoErr(t, err, "new sumvec failed")
	got := testPrio3(t, s, input)
	test.CheckOk(got != nil, "prio3 sumvec failed", t)
	if !slices.Equal(*got, want) {
		test.ReportError(t, *got, want)
	}
}

func TestHistogram(t *testing.T) {
	input := []uint64{2, 1, 1, 2, 0, 3, 3, 3, 3, 3}
	want := []uint64{
		1, // how many zeros
		2, // how many ones
		2, // how many twos
		5, // how many threes
	}
	h, err := histogram.New(NumShares, 4, 3, Context)
	test.CheckNoErr(t, err, "new histogram failed")
	got := testPrio3(t, h, input)
	test.CheckOk(got != nil, "prio3 histogram failed", t)
	if !slices.Equal(*got, want) {
		test.ReportError(t, *got, want)
	}
}

func TestMultiHotCountVec(t *testing.T) {
	const MaxWeight = 2
	input := [][]bool{
		{false, false, false, false, false}, // Hamming weight = 0 <= MaxWeight
		{false, false, false, false, true},  // Hamming weight = 1 <= MaxWeight
		{true, false, false, false, true},   // Hamming weight = 2 <= MaxWeight
	}
	// Element-wise count of binary vectors of weight at most MaxWeight.
	want := []uint64{1, 0, 0, 0, 2}
	m, err := mhcv.New(NumShares, 5, MaxWeight, 3, Context)
	test.CheckNoErr(t, err, "new MultiHotCountVec failed")
	got := testPrio3(t, m, input)
	test.CheckOk(got != nil, "prio3 multiHotCountVec failed", t)
	if !slices.Equal(*got, want) {
		test.ReportError(t, *got, want)
	}
}

func testPrio3[
	P Prio3[
		Measurement, Aggregate,
		AggShare, InputShare, Nonce, OutShare, PrepMessage, PrepShare, PrepState,
		PublicShare, VerifyKey,
	],
	Measurement, Aggregate any,
	AggShare, InputShare, Nonce, OutShare, PrepMessage, PrepShare, PrepState,
	PublicShare, VerifyKey any,
](t testing.TB, p P, measurements []Measurement) *Aggregate {
	params := p.Params()
	shares := params.Shares()
	verifyKey := fromReader[VerifyKey](t, rand.Reader)

	aggShares := make([]AggShare, shares)
	for i := range aggShares {
		aggShares[i] = p.AggregateInit()
	}

	for _, mi := range measurements {
		nonce := fromReader[Nonce](t, rand.Reader)
		randb := make([]byte, params.RandSize())
		_, err := io.ReadFull(rand.Reader, randb)
		test.CheckNoErr(t, err, "read rand bytes failed")

		var pubShare PublicShare
		var inputShares []InputShare
		pubShare, inputShares, err = p.Shard(mi, &nonce, randb)
		test.CheckNoErr(t, err, "Shard failed")
		testMarshal(t, &pubShare, &params)
		for i := range inputShares {
			testMarshal(t, &inputShares[i], &params, uint(i))
		}

		var prepStates []*PrepState
		var outboundPrepShares []PrepShare
		for i := range shares {
			state, share, errx := p.PrepInit(
				&verifyKey, &nonce, i, pubShare, inputShares[i])
			test.CheckNoErr(t, errx, "PrepInit failed")
			testMarshal(t, state, &params)
			testMarshal(t, share, &params)

			prepStates = append(prepStates, state)
			outboundPrepShares = append(outboundPrepShares, *share)
		}

		var prepMsg *PrepMessage
		prepMsg, err = p.PrepSharesToPrep(outboundPrepShares)
		test.CheckNoErr(t, err, "PrepSharesToPrep failed")
		testMarshal(t, prepMsg, &params)

		var outShare *OutShare
		for i := range shares {
			outShare, err = p.PrepNext(prepStates[i], prepMsg)
			test.CheckNoErr(t, err, "PrepNext failed")
			testMarshal(t, outShare, &params)
			p.AggregateUpdate(&aggShares[i], outShare)
		}
	}

	testMarshal(t, &aggShares[0], &params)
	numMeas := uint(len(measurements))
	aggResult, err := p.Unshard(aggShares, numMeas)
	test.CheckNoErr(t, err, "unshard failed")

	return aggResult
}

func BenchmarkCount(b *testing.B) {
	c, err := count.New(NumShares, Context)
	test.CheckNoErr(b, err, "new Count failed")
	benchmarkPrio3(b, c, []bool{true, true, false})
}

func BenchmarkSum(b *testing.B) {
	s, err := sum.New(NumShares, 4, Context)
	test.CheckNoErr(b, err, "new Sum failed")
	benchmarkPrio3(b, s, []uint64{1, 2, 3})
}

func BenchmarkSumVec(b *testing.B) {
	s, err := sumvec.New(NumShares, 2, 3, 2, Context)
	test.CheckNoErr(b, err, "new SumVec failed")
	benchmarkPrio3(b, s, [][]uint64{{1, 2}, {2, 0}})
}

func BenchmarkHistogram(b *testing.B) {
	h, err := histogram.New(NumShares, 4, 2, Context)
	test.CheckNoErr(b, err, "new Histogram failed")
	benchmarkPrio3(b, h, []uint64{1, 2, 2, 0})
}

func BenchmarkMultiHotCountVec(b *testing.B) {
	m, err := mhcv.New(NumShares, 3, 2, 3, Context)
	test.CheckNoErr(b, err, "new MultiHotCountVec failed")
	benchmarkPrio3(b, m, [][]bool{
		{false, false, true},
		{false, true, false},
		{false, false, true},
	})
}

func benchmarkPrio3[
	P Prio3[
		Measurement, Aggregate,
		AggShare, InputShare, Nonce, OutShare, PrepMessage, PrepShare, PrepState,
		PublicShare, VerifyKey,
	],
	Measurement, Aggregate any,
	AggShare, InputShare, Nonce, OutShare, PrepMessage, PrepShare, PrepState,
	PublicShare, VerifyKey any,
](b *testing.B, p P, meas []Measurement) {
	for i := 0; i < b.N; i++ {
		_ = testPrio3(b, p, meas)
	}
}
