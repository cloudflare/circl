// Package prio3 supports a variety of verifiable distributed aggregation functions.
//
// Clients protect the privacy of their measurements by secret sharing them
// and distributing the shares among the Aggregators.
// To ensure each measurement is valid, the Aggregators run a multi-party
// computation on their shares, the result of which is the output of the
// arithmetic circuit.
// This involves verification of a Fully Linear Proof (FLP) that specifies
// the types of measurements.
//
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf-13#section-7
package prio3

import (
	"crypto/subtle"
	"errors"

	"github.com/cloudflare/circl/vdaf/prio3/arith"
	"github.com/cloudflare/circl/vdaf/prio3/internal/cursor"
)

// Prio3 supports a variety of verifiable distributed aggregation functions.
// An instance is parametrized by the type of measurement and aggregated data,
// as well as the field to perform arithmetic operations.
type Prio3[
	Measurement, Aggregate any,
	T flp[Measurement, Aggregate, V, E, F],
	V arith.Vec[V, E], E arith.Elt, F arith.Fp[E],
] struct {
	flp      T
	xof      xofTS[V, E]
	randSize uint
	shares   uint8
}

func New[
	T flp[Measurement, Aggregate, V, E, F],
	Measurement, Aggregate any,
	V arith.Vec[V, E], E arith.Elt, F arith.Fp[E],
](f T, algorithmID uint32, numShares uint8, context []byte,
) (v Prio3[Measurement, Aggregate, T, V, E, F], err error) {
	if numShares < 2 {
		return v, ErrNumShares
	}

	v.flp = f
	v.xof, err = NewXof[V](algorithmID, context)
	if err != nil {
		return v, err
	}

	v.shares = numShares
	v.randSize = SeedSize * uint(numShares)
	if f.JointRandLength() > 0 {
		v.randSize *= 2
	}

	return v, nil
}

// Shard takes a measurement and return a set of shares and a public share
// used for verification.
//
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf-13#section-7.2.1
func (v *Prio3[M, A, T, V, E, F]) Shard(
	measurement M, nonce *Nonce, rand []byte,
) (PublicShare, []InputShare[V, E], error) {
	if len(rand) != int(v.randSize) {
		return nil, nil, ErrRandSize
	}

	meas, err := v.flp.Encode(measurement)
	if err != nil {
		return nil, nil, err
	}

	if v.flp.JointRandLength() == 0 {
		inputShare, err := v.shardNoJointRand(meas, rand)
		return nil, inputShare, err
	} else {
		return v.shardWithJointRand(meas, nonce, rand)
	}
}

// FLPs without joint randomness.
//
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf-13#section-7.2.1.1
func (v *Prio3[M, A, T, V, E, F]) shardNoJointRand(
	meas V, seeds []byte,
) ([]InputShare[V, E], error) {
	// Each Aggregator's input share contains its measurement share
	// and its share of the proof.
	params := v.Params()
	inputShares := make([]InputShare[V, E], v.shares)
	inputShares[0].leader = new(InputShareLeader[V, E]).New(&params)

	seedsCur := cursor.New(seeds)
	for i := 1; i < len(inputShares); i++ {
		inputShares[i].helper = &InputShareHelper{
			share: Seed(seedsCur.Next(SeedSize)),
			blind: nil,
		}
	}

	// Generate proof of valid measurement.
	proveSeed := Seed(seedsCur.Next(SeedSize))
	proveRands := arith.NewVec[V](params.ProveRandLength())
	err := v.xof.proveRands(proveRands, &proveSeed)
	if err != nil {
		return nil, err
	}

	proveRand := proveRands[:params.ProveRandLength()]
	proof := v.flp.Prove(meas, proveRand, nil)

	// Shard the encoded measurement and proof into shares.
	copy(inputShares[0].leader.measShare, meas)
	copy(inputShares[0].leader.proofShare, proof)
	m := arith.NewVec[V](params.MeasurementLength())
	p := arith.NewVec[V](params.ProofLength())
	for i := 1; i < len(inputShares); i++ {
		share := &inputShares[i].helper.share
		err = v.xof.helperMeasShare(m, uint8(i), share)
		if err != nil {
			return nil, err
		}

		inputShares[0].leader.measShare.SubAssign(m)

		err = v.xof.helperProofsShare(p, uint8(i), share)
		if err != nil {
			return nil, err
		}

		inputShares[0].leader.proofShare.SubAssign(p)
	}

	return inputShares, nil
}

// FLPs with joint randomness.
//
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf-13#section-7.2.1.2
func (v *Prio3[M, A, T, V, E, F]) shardWithJointRand(
	meas V, nonce *Nonce, seeds []byte,
) (PublicShare, []InputShare[V, E], error) {
	// Each Aggregator's input share contains its measurement share,
	// share of proof, and blind. The public share contains the
	// Aggregators' joint randomness parts.
	params := v.Params()
	inputShares := make([]InputShare[V, E], v.shares)
	inputShares[0].leader = new(InputShareLeader[V, E]).New(&params)

	seedsCur := cursor.New(seeds)
	for i := 1; i < len(inputShares); i++ {
		inputShares[i].helper = &InputShareHelper{
			share: Seed(seedsCur.Next(SeedSize)),
			blind: (*Seed)(seedsCur.Next(SeedSize)),
		}
	}
	inputShares[0].leader.blind = (*Seed)(seedsCur.Next(SeedSize))

	// Shard the encoded measurement into shares and compute the
	// joint randomness parts.
	copy(inputShares[0].leader.measShare, meas)

	var jointRandParts PublicShare
	jointRandParts.New(&params)
	jointRandPartsCur := cursor.New(jointRandParts)
	jrpLeader := jointRandPartsCur.Next(SeedSize)

	m := arith.NewVec[V](params.MeasurementLength())
	encM := make([]byte, m.Size())
	for i := 1; i < len(inputShares); i++ {
		err := v.xof.helperMeasShareEnc(
			encM[:0], m, uint8(i), &inputShares[i].helper.share)
		if err != nil {
			return nil, nil, err
		}

		err = v.xof.jointRandPart(jointRandPartsCur.Next(SeedSize),
			inputShares[i].helper.blind, uint8(i), nonce, encM)
		if err != nil {
			return nil, nil, err
		}

		inputShares[0].leader.measShare.SubAssign(m)
	}

	// Calculate leader's jointRandPart after leader's measShare
	// has been calculated.
	measShareEnc, err := inputShares[0].leader.measShare.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	err = v.xof.jointRandPart(
		jrpLeader, inputShares[0].leader.blind, 0, nonce, measShareEnc)
	if err != nil {
		return nil, nil, err
	}

	// Generate proof of valid measurement.
	proveSeed := Seed(seedsCur.Next(SeedSize))
	proveRands := arith.NewVec[V](params.ProveRandLength())
	err = v.xof.proveRands(proveRands, &proveSeed)
	if err != nil {
		return nil, nil, err
	}

	proveRand := proveRands[:params.ProveRandLength()]

	jrSeed, err := v.xof.jointRandSeed(jointRandParts)
	if err != nil {
		return nil, nil, err
	}

	jointRands := arith.NewVec[V](params.JointRandLength())
	err = v.xof.jointRands(jointRands, &jrSeed)
	if err != nil {
		return nil, nil, err
	}

	jointRand := jointRands[:params.JointRandLength()]
	proof := v.flp.Prove(meas, proveRand, jointRand)

	// Shard the proof into shares.
	copy(inputShares[0].leader.proofShare, proof)
	p := arith.NewVec[V](params.ProofLength())
	for i := 1; i < len(inputShares); i++ {
		err = v.xof.helperProofsShare(p, uint8(i), &inputShares[i].helper.share)
		if err != nil {
			return nil, nil, err
		}

		inputShares[0].leader.proofShare.SubAssign(p)
	}

	return jointRandParts, inputShares, nil
}

// PrepInit is used by each aggregator to begin the preparation phase.
//
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf-13#section-7.2.2
func (v *Prio3[M, A, T, V, E, F]) PrepInit(
	verifyKey *VerifyKey, nonce *Nonce, aggID uint8,
	ps PublicShare, inputShare InputShare[V, E],
) (*PrepState[V, E], *PrepShare[V, E], error) {
	params := v.Params()
	if aggID > v.shares {
		return nil, nil, ErrAggID
	}

	share, err := v.getInputShareContent(aggID, inputShare, &params)
	if err != nil {
		return nil, nil, err
	}

	prepShare := new(PrepShare[V, E])
	prepState := new(PrepState[V, E])
	prepState.outShare = v.flp.Truncate(share.measShare)

	// Compute the joint randomness.
	var jointRand V
	jointRandLen := params.JointRandLength()
	if jointRandLen > 0 {
		if share.blind == nil || len(ps) == 0 {
			return nil, nil, ErrJointRand
		}

		var measShareEnc []byte
		measShareEnc, err = share.measShare.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}

		prepShare.jointRandPart = &Seed{}
		err = v.xof.jointRandPart(prepShare.jointRandPart[:],
			share.blind, aggID, nonce, measShareEnc)
		if err != nil {
			return nil, nil, err
		}

		prepState.correctedJointRandSeed = &Seed{}
		*prepState.correctedJointRandSeed, err = v.xof.jointRandSeed(ps)
		if err != nil {
			return nil, nil, err
		}

		jointRands := arith.NewVec[V](params.JointRandLength())
		err = v.xof.jointRands(jointRands, prepState.correctedJointRandSeed)
		if err != nil {
			return nil, nil, err
		}

		jointRand = jointRands[:jointRandLen]
	}

	// Query the measurement and proof share.
	queryRands := arith.NewVec[V](params.QueryRandLength())
	err = v.xof.queryRands(queryRands, verifyKey, nonce)
	if err != nil {
		return nil, nil, err
	}

	proofShare := share.proofShare[:params.ProofLength()]
	queryRand := queryRands[:params.QueryRandLength()]

	prepShare.verifiersShare, err = v.flp.Query(
		share.measShare, proofShare, queryRand, jointRand, v.shares)
	if err != nil {
		return nil, nil, err
	}

	return prepState, prepShare, nil
}

// PrepSharesToPrep is the deterministic preparation message pre-processing
// algorithm. It combines the prep shares produced by the Aggregators in the
// previous round into the prep message consumed by each Aggregator to start
// the next round.
//
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf-13#section-7.2.2
func (v *Prio3[M, A, T, V, E, F]) PrepSharesToPrep(
	prepShares []PrepShare[V, E],
) (*PrepMessage, error) {
	params := v.Params()
	msg := new(PrepMessage)
	// Unshard the verifier shares into the verifier message.
	verifierLen := params.VerifierLength()
	verifiers := arith.NewVec[V](verifierLen)
	for i := range prepShares {
		verifiers.AddAssign(prepShares[i].verifiersShare)
	}

	// Verify that each proof is well-formed and input is valid.
	verifier := verifiers[:verifierLen]
	if !v.flp.Decide(verifier) {
		return nil, ErrProofVerify
	}

	// Combine the joint randomness parts computed by the
	// Aggregators into the true joint randomness seed. This is
	// used in the last step.
	if params.JointRandLength() > 0 {
		jointRandParts := make([]byte, 0, SeedSize*uint(v.shares))
		for i := range prepShares {
			if prepShares[i].jointRandPart == nil {
				return nil, ErrJointRand
			}

			jointRandParts = append(
				jointRandParts, prepShares[i].jointRandPart[:]...)
		}

		jointRandSeed, err := v.xof.jointRandSeed(jointRandParts)
		if err != nil {
			return nil, err
		}

		msg.joinRand = &jointRandSeed
	}

	return msg, nil
}

// PrepNext is used by each aggregator to produce its output share.
//
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf-13#section-7.2.2
func (v *Prio3[M, A, T, V, E, F]) PrepNext(
	state *PrepState[V, E], msg *PrepMessage,
) (*OutShare[V, E], error) {
	if msg != nil && state != nil && msg.joinRand != nil &&
		state.correctedJointRandSeed != nil {
		if subtle.ConstantTimeCompare(
			msg.joinRand[:], state.correctedJointRandSeed[:]) != 1 {
			return nil, ErrJointRand
		}
	}

	return &OutShare[V, E]{state.outShare}, nil
}

// AggregateInit is used to start aggregation.
//
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf-13#section-7.2.4
func (v *Prio3[M, A, T, V, E, F]) AggregateInit() (s AggShare[V, E]) {
	s.share = arith.NewVec[V](v.flp.OutputLength())
	return
}

// AggregateUpdate aggregates an output share into an aggregation share.
//
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf-13#section-7.2.4
func (v *Prio3[M, A, T, V, E, F]) AggregateUpdate(
	aggShare *AggShare[V, E], outShare *OutShare[V, E],
) {
	aggShare.share.AddAssign(outShare.share)
}

// aggregateMerge merges several aggregation shares.
//
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf-13#section-7.2.4
func (v *Prio3[M, A, T, V, E, F]) aggregateMerge(
	aggShares []AggShare[V, E],
) (s AggShare[V, E]) {
	s = v.AggregateInit()
	for i := range aggShares {
		s.share.AddAssign(aggShares[i].share)
	}

	return
}

// Unshard is used by the Collector to recover the aggregate result from a set
// of aggregation shares.
//
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf-13#section-7.2.5
func (v *Prio3[M, A, T, V, E, F]) Unshard(
	aggShares []AggShare[V, E], numMeas uint,
) (*A, error) {
	if len(aggShares) != int(v.shares) {
		return nil, ErrAggShareSize
	}

	s := v.aggregateMerge(aggShares)
	return v.flp.Decode(s.share, numMeas)
}

func (v *Prio3[M, A, T, V, E, F]) getInputShareContent(
	aggID uint8, inShare InputShare[V, E], params *Params,
) (s inputShareContent[V, E], err error) {
	switch true {
	case aggID == 0 && inShare.leader != nil:
		return inShare.leader.inputShareContent, nil
	case aggID != 0 && inShare.helper != nil:
		s.New(params)
		share := &inShare.helper.share
		err = v.xof.helperMeasShare(s.measShare, aggID, share)
		if err != nil {
			return s, err
		}

		err = v.xof.helperProofsShare(s.proofShare, aggID, share)
		if err != nil {
			return s, err
		}

		s.blind = inShare.helper.blind
		return s, nil
	default:
		return s, ErrShare
	}
}

type Params struct {
	jointRandLen   uint
	measurementLen uint
	outputLen      uint
	evalOutputLen  uint
	queryRandLen   uint
	proveRandLen   uint
	proofLen       uint
	verifierLen    uint
	randSize       uint
	shares         uint8
}

func (p *Params) JointRandLength() uint   { return p.jointRandLen }
func (p *Params) MeasurementLength() uint { return p.measurementLen }
func (p *Params) OutputLength() uint      { return p.outputLen }
func (p *Params) EvalOutputLength() uint  { return p.evalOutputLen }
func (p *Params) QueryRandLength() uint   { return p.queryRandLen }
func (p *Params) ProveRandLength() uint   { return p.proveRandLen }
func (p *Params) ProofLength() uint       { return p.proofLen }
func (p *Params) VerifierLength() uint    { return p.verifierLen }
func (p *Params) RandSize() uint          { return p.randSize }
func (p *Params) Shares() uint8           { return p.shares }

func (v *Prio3[M, A, T, V, E, F]) Params() Params {
	return Params{
		jointRandLen:   v.flp.JointRandLength(),
		measurementLen: v.flp.MeasurementLength(),
		outputLen:      v.flp.OutputLength(),
		evalOutputLen:  v.flp.EvalOutputLength(),
		queryRandLen:   v.flp.QueryRandLength(),
		proveRandLen:   v.flp.ProveRandLength(),
		proofLen:       v.flp.ProofLength(),
		verifierLen:    v.flp.VerifierLength(),
		randSize:       v.randSize,
		shares:         v.shares,
	}
}

type flp[
	Measurement, AggResult any,
	V arith.Vec[V, E], E arith.Elt, F arith.Fp[E],
] interface {
	MeasurementLength() uint
	JointRandLength() uint
	OutputLength() uint
	EvalOutputLength() uint
	ProveRandLength() uint
	ProofLength() uint
	VerifierLength() uint
	QueryRandLength() uint
	// Prove returns a proof attesting to the validity of the given measurement.
	Prove(meas, proveRand, jointRand V) V
	// Query is the linear Query algorithm run by each verifier on its share of
	// the measurement and proof.
	Query(measShare, proofShare, queryRnd, jointRnd V, shares uint8) (V, error)
	// Decide returns true if the measurement from which it was generated is
	// valid.
	Decide(V) bool
	// Encode returns a vector of MeasurementLength() elements representing
	// a measurement of type [Measurement].
	Encode(Measurement) (V, error)
	// Truncate returns a vector of OutputLength() elements representing
	// (a share of) an aggregatable output.
	Truncate(V) V
	// Decode returns an aggregate result of type [AggResult].
	// This computation may depend on the number of outputs aggregated.
	Decode(V, uint) (*AggResult, error)
}

var (
	ErrNumShares     = errors.New("invalid numshares, must be greater than 1")
	ErrContextSize   = errors.New("invalid context length, (0, MaxContextSize)")
	ErrNonceSize     = errors.New("invalid nonce length, (NonceSize)")
	ErrVerifyKeySize = errors.New("invalid verify key length, (VerifyKeySize)")
	ErrRandSize      = errors.New("invalid randomness length")
	ErrAggShareSize  = errors.New("invalid aggregate shares length")
	ErrAggID         = errors.New("invalid aggregation ID")
	ErrJointRand     = errors.New("invalid joint randomness")
	ErrShare         = errors.New("share was not provided")
	ErrProofVerify   = errors.New("proof verifier check failed")
)
