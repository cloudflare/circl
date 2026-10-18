package prio3

import (
	"errors"
	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/vdaf/prio3/arith"
	"golang.org/x/crypto/cryptobyte"
)

const (
	SeedSize      uint = 32 // Size of Seed in bytes.
	NonceSize     uint = 16 // Size of Nonce in bytes.
	VerifyKeySize uint = 32 // Size of VerifyKey in bytes.
)

type (
	// Nonce is a public random value associated with the report.
	Nonce [NonceSize]byte
	// VerifyKey is a secret verification key held by each of the Aggregators.
	// This key is used to verify validity of the output shares they compute.
	VerifyKey [VerifyKeySize]byte
	// Seed is used to feed an extendable output function.
	Seed [SeedSize]byte
)

func (s *Seed) Marshal(b *cryptobyte.Builder) error {
	b.AddBytes(s[:])
	return nil
}

func (s *Seed) Unmarshal(str *cryptobyte.String) bool {
	return str.CopyBytes((*s)[:])
}

// PublicShare must be distributed to each of the Aggregators.
// Its content depends on whether joint randomness is required for the
// underlying FLP.
// If joint randomness is not used, then the public share is an empty slice.
//
//	struct {
//	    Prio3Seed joint_rand_parts[SEED_SIZE * prio3.SHARES];
//	} Prio3PublicShareWithJointRand;
type PublicShare []byte

func (s *PublicShare) New(p *Params) *PublicShare {
	var n uint
	if p.JointRandLength() > 0 {
		n = SeedSize * uint(p.shares)
	}
	*s = make([]byte, n)
	return s
}

func (s *PublicShare) Marshal(b *cryptobyte.Builder) error {
	b.AddBytes(*s)
	return nil
}

func (s *PublicShare) MarshalBinary() ([]byte, error) {
	return conv.MarshalBinaryLen(s, uint(len(*s)))
}

func (s *PublicShare) Unmarshal(str *cryptobyte.String) bool {
	return str.CopyBytes(*s)
}

func (s *PublicShare) UnmarshalBinary(b []byte) error {
	return conv.UnmarshalBinary(s, b)
}

type inputShareContent[V arith.Vec[V, E], E arith.Elt] struct {
	blind      *Seed
	proofShare V
	measShare  V
}

func (s *inputShareContent[V, E]) New(p *Params) *inputShareContent[V, E] {
	s.measShare = arith.NewVec[V](p.MeasurementLength())
	s.proofShare = arith.NewVec[V](p.ProofLength())
	if p.JointRandLength() > 0 {
		s.blind = &Seed{}
	} else {
		s.blind = nil
	}
	return s
}

func (s *inputShareContent[V, E]) Marshal(b *cryptobyte.Builder) error {
	b.AddValue(s.measShare)
	b.AddValue(s.proofShare)
	if s.blind != nil {
		b.AddValue(s.blind)
	}
	return nil
}

func (s *inputShareContent[V, E]) Unmarshal(str *cryptobyte.String) bool {
	ok := s.measShare.Unmarshal(str) && s.proofShare.Unmarshal(str)
	if s.blind != nil {
		ok = ok && s.blind.Unmarshal(str)
	}
	return ok
}

// InputShareLeader represents one of these two structures.
//
//	struct {
//	    Prio3Field meas_share[F * prio3.flp.MEAS_LEN];
//	    Prio3Field proofs_share[F * prio3.flp.PROOF_LEN * prio3.PROOFS];
//	} Prio3LeaderShare;
//
//	struct {
//	    Prio3LeaderShare inner;
//	    Prio3Seed blind;
//	} Prio3LeaderShareWithJointRand;
type InputShareLeader[V arith.Vec[V, E], E arith.Elt] struct {
	inputShareContent[V, E]
}

func (s *InputShareLeader[V, E]) New(p *Params) *InputShareLeader[V, E] {
	s.inputShareContent.New(p)
	return s
}

// InputShareHelper represents one of these two structures.
//
//	struct {
//	    Prio3Seed share;
//	} Prio3HelperShare;
//
//	struct {
//	    Prio3HelperShare inner;
//	    Prio3Seed blind;
//	} Prio3HelperShareWithJointRand;
type InputShareHelper struct {
	blind *Seed
	share Seed
}

func (s *InputShareHelper) New(p *Params) *InputShareHelper {
	s.share = Seed{}
	if p.JointRandLength() > 0 {
		s.blind = &Seed{}
	} else {
		s.blind = nil
	}
	return s
}

func (s *InputShareHelper) Marshal(b *cryptobyte.Builder) error {
	b.AddValue(&s.share)
	if s.blind != nil {
		b.AddValue(s.blind)
	}
	return nil
}

func (s *InputShareHelper) Unmarshal(str *cryptobyte.String) bool {
	ok := s.share.Unmarshal(str)
	if s.blind != nil {
		ok = ok && s.blind.Unmarshal(str)
	}
	return ok
}

// InputShare is a generic struct that stores shares for the leader or helper.
type InputShare[V arith.Vec[V, E], E arith.Elt] struct {
	leader *InputShareLeader[V, E]
	helper *InputShareHelper
}

func (s *InputShare[V, E]) New(p *Params, aggID uint) *InputShare[V, E] {
	if aggID == 0 {
		s.leader = new(InputShareLeader[V, E]).New(p)
		s.helper = nil
	} else {
		s.helper = new(InputShareHelper).New(p)
		s.leader = nil
	}
	return s
}

func (s *InputShare[V, E]) MarshalBinary() ([]byte, error) {
	return conv.MarshalBinary(s)
}

func (s *InputShare[V, E]) UnmarshalBinary(b []byte) error {
	return conv.UnmarshalBinary(s, b)
}

func (s *InputShare[V, E]) Marshal(b *cryptobyte.Builder) error {
	switch true {
	case s.leader != nil && s.helper == nil:
		b.AddValue(s.leader)
	case s.leader == nil && s.helper != nil:
		b.AddValue(s.helper)
	default:
		return ErrShare
	}
	return nil
}

func (s *InputShare[V, E]) Unmarshal(str *cryptobyte.String) bool {
	switch true {
	case s.leader != nil && s.helper == nil:
		return s.leader.Unmarshal(str)
	case s.leader == nil && s.helper != nil:
		return s.helper.Unmarshal(str)
	default:
		return false
	}
}

// InputShareHelper represents one of these two structures.
//
//	struct {
//	    Prio3Field verifiers_share[F * V];
//	} Prio3PrepShare;
//
//	struct {
//	    Prio3Field verifiers_share[F * V];
//	    Prio3Seed joint_rand_part;
//	} Prio3PrepShareWithJointRand;
type PrepShare[V arith.Vec[V, E], E arith.Elt] struct {
	jointRandPart  *Seed
	verifiersShare V
}

func (s *PrepShare[V, E]) New(p *Params) *PrepShare[V, E] {
	s.verifiersShare = arith.NewVec[V](p.VerifierLength())
	if p.JointRandLength() > 0 {
		s.jointRandPart = &Seed{}
	} else {
		s.jointRandPart = nil
	}
	return s
}

func (s *PrepShare[V, E]) MarshalBinary() ([]byte, error) {
	return conv.MarshalBinary(s)
}

func (s *PrepShare[V, E]) UnmarshalBinary(b []byte) error {
	return conv.UnmarshalBinary(s, b)
}

func (s *PrepShare[V, E]) Marshal(b *cryptobyte.Builder) error {
	b.AddValue(s.verifiersShare)
	if s.jointRandPart != nil {
		b.AddValue(s.jointRandPart)
	}
	return nil
}

func (s *PrepShare[V, E]) Unmarshal(str *cryptobyte.String) bool {
	ok := s.verifiersShare.Unmarshal(str)
	if s.jointRandPart != nil {
		ok = ok && s.jointRandPart.Unmarshal(str)
	}
	return ok
}

type PrepState[V arith.Vec[V, E], E arith.Elt] struct {
	correctedJointRandSeed *Seed
	outShare               V
}

func (s *PrepState[V, E]) New(p *Params) *PrepState[V, E] {
	s.outShare = arith.NewVec[V](p.OutputLength())
	if p.JointRandLength() > 0 {
		s.correctedJointRandSeed = &Seed{}
	} else {
		s.correctedJointRandSeed = nil
	}
	return s
}

func (s *PrepState[V, E]) MarshalBinary() ([]byte, error) {
	return conv.MarshalBinary(s)
}

func (s *PrepState[V, E]) UnmarshalBinary(b []byte) error {
	return conv.UnmarshalBinary(s, b)
}

func (s *PrepState[V, E]) Marshal(b *cryptobyte.Builder) error {
	b.AddValue(s.outShare)
	if s.correctedJointRandSeed != nil {
		b.AddValue(s.correctedJointRandSeed)
	}
	return nil
}

func (s *PrepState[V, E]) Unmarshal(str *cryptobyte.String) bool {
	ok := s.outShare.Unmarshal(str)
	if s.correctedJointRandSeed != nil {
		ok = ok && s.correctedJointRandSeed.Unmarshal(str)
	}
	return ok
}

// PrepMessage represents the following structure.
//
//	struct {
//	    Prio3Seed joint_rand;
//	} Prio3PrepMessageWithJointRand;
type PrepMessage struct{ joinRand *Seed }

func (s *PrepMessage) New(p *Params) *PrepMessage {
	if p.JointRandLength() > 0 {
		s.joinRand = &Seed{}
	} else {
		s.joinRand = nil
	}
	return s
}

func (s *PrepMessage) MarshalBinary() ([]byte, error) {
	return conv.MarshalBinary(s)
}

func (s *PrepMessage) UnmarshalBinary(b []byte) error {
	return conv.UnmarshalBinary(s, b)
}

func (s *PrepMessage) Marshal(b *cryptobyte.Builder) error {
	if s.joinRand != nil {
		b.AddValue(s.joinRand)
	}
	return nil
}

func (s *PrepMessage) Unmarshal(str *cryptobyte.String) bool {
	if s.joinRand != nil {
		return s.joinRand.Unmarshal(str)
	}
	return true
}

type OutShare[V arith.Vec[V, E], E arith.Elt] struct{ share V }

func (s *OutShare[V, E]) New(p *Params) *OutShare[V, E] {
	s.share = arith.NewVec[V](p.OutputLength())
	return s
}

func (s *OutShare[V, E]) MarshalBinary() ([]byte, error) {
	return conv.MarshalBinaryLen(s, s.share.Size())
}

func (s *OutShare[V, E]) UnmarshalBinary(b []byte) error {
	return conv.UnmarshalBinary(s, b)
}

func (s *OutShare[V, E]) Marshal(b *cryptobyte.Builder) error {
	b.AddValue(s.share)
	return nil
}

func (s *OutShare[V, E]) Unmarshal(str *cryptobyte.String) bool {
	return s.share.Unmarshal(str)
}

// ExportBytes returns the portable binary encoding of the OutShare.
func (s *OutShare[V, E]) ExportBytes() ([]byte, error) {
	return s.MarshalBinary()
}

// ImportBytes sets the OutShare from a portable binary encoding.
func (s *OutShare[V, E]) ImportBytes(data []byte) error {
	return s.UnmarshalBinary(data)
}

// ExportRaw returns the underlying vector as a byte slice.
func (s *OutShare[V, E]) ExportRaw() ([]byte, error) {
	if b, ok := any(s.share).(interface{ ExportRaw() ([]byte, error) }); ok {
		return b.ExportRaw()
	}
	return nil, errors.New("ExportRaw: underlying vector does not support ExportRaw")
}

// ImportRaw sets the underlying vector from a byte slice.
func (s *OutShare[V, E]) ImportRaw(data []byte) error {
	if b, ok := any(&s.share).(interface{ ImportRaw([]byte) error }); ok {
		return b.ImportRaw(data)
	}
	return errors.New("ImportRaw: underlying vector does not support ImportRaw")
}

// AggShare represents the following structure.
//
//	struct {
//	    Prio3Field agg_share[F * prio3.flp.OUTPUT_LEN];
//	} Prio3AggShare;
type AggShare[V arith.Vec[V, E], E arith.Elt] struct{ share V }

func (s *AggShare[V, E]) New(p *Params) *AggShare[V, E] {
	s.share = arith.NewVec[V](p.OutputLength())
	return s
}

func (s *AggShare[V, E]) MarshalBinary() ([]byte, error) {
	return conv.MarshalBinaryLen(s, s.share.Size())
}

func (s *AggShare[V, E]) UnmarshalBinary(b []byte) error {
	return conv.UnmarshalBinary(s, b)
}

func (s *AggShare[V, E]) Marshal(b *cryptobyte.Builder) error {
	b.AddValue(s.share)
	return nil
}

func (s *AggShare[V, E]) Unmarshal(str *cryptobyte.String) bool {
	return s.share.Unmarshal(str)
}
