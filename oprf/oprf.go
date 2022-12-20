// Package oprf provides Verifiable, Oblivious Pseudo-Random Functions.
//
// An Oblivious Pseudorandom Function (OPRFs) is a two-party protocol for
// computing the output of a PRF. One party (the server) holds the PRF secret
// key, and the other (the client) holds the PRF input.
//
// This package is compatible with the OPRF specification at draft-irtf-cfrg-voprf [1].
//
// # Protocol Overview
//
// This diagram shows the steps of the protocol that are common for all operation modes.
//
//	Client(info*)                               Server(sk, pk, info*)
//	=================================================================
//	finData, evalReq = Blind(input)
//
//	                            evalReq
//	                          ---------->
//
//	                            evaluation = Evaluate(evalReq, info*)
//
//	                           evaluation
//	                          <----------
//
//	output = Finalize(finData, evaluation, info*)
//
// # Operation Modes
//
// Each operation mode provides different properties to the PRF.
//
// Base Mode: Provides obliviousness to the PRF evaluation, i.e., it ensures
// that the server does not learn anything about the client's input and output
// during the Evaluation step.
//
// Verifiable Mode: Extends the Base mode allowing the client to verify that
// Server used the private key that corresponds to the public key.
//
// Partial Oblivious Mode: Extends the Verifiable mode by including shared
// public information to the PRF input.
//
// All three modes can perform batches of PRF evaluations, so passing an array
// of inputs will produce an array of outputs.
//
// # References
//
// [1] draft-irtf-cfrg-voprf: https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf
package oprf

import (
	"crypto"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"math"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/zk/dleq"
)

const (
	version          = "OPRFV1-"
	finalizeDST      = "Finalize"
	hashToGroupDST   = "HashToGroup-"
	hashToScalarDST  = "HashToScalar-"
	deriveKeyPairDST = "DeriveKeyPair"
	infoLabel        = "Info"
)

type Mode = uint8

const (
	BaseMode             Mode = 0x00
	VerifiableMode       Mode = 0x01
	PartialObliviousMode Mode = 0x02
)

func isValidMode(m Mode) bool {
	return m == BaseMode || m == VerifiableMode || m == PartialObliviousMode
}

type Suite interface {
	Identifier() string
	Group() group.Group
	Hash() crypto.Hash
	cannotBeImplementedExternally()
}

var (
	// SuiteRistretto255 represents the OPRF with Ristretto255 and SHA-512
	SuiteRistretto255 Suite = params{identifier: "ristretto255-SHA512", group: group.Ristretto255, hash: crypto.SHA512}
	// SuiteP256 represents the OPRF with P-256 and SHA-256.
	SuiteP256 Suite = params{identifier: "P256-SHA256", group: group.P256, hash: crypto.SHA256}
	// SuiteP384 represents the OPRF with P-384 and SHA-384.
	SuiteP384 Suite = params{identifier: "P384-SHA384", group: group.P384, hash: crypto.SHA384}
	// SuiteP521 represents the OPRF with P-521 and SHA-512.
	SuiteP521 Suite = params{identifier: "P521-SHA512", group: group.P521, hash: crypto.SHA512}
)

func GetSuite(identifier string) (Suite, error) {
	for _, suite := range []Suite{SuiteRistretto255, SuiteP256, SuiteP384, SuiteP521} {
		if suite.Identifier() == identifier {
			return suite, nil
		}
	}
	return nil, ErrInvalidSuite
}

func NewClient(s Suite) Client {
	p := s.(params)
	p.m = BaseMode

	return Client{client{p}}
}

func NewVerifiableClient(s Suite, server *PublicKey) VerifiableClient {
	p, ok := s.(params)
	if !ok || server == nil {
		panic(ErrNoKey)
	}
	p.m = VerifiableMode

	return VerifiableClient{client{p}, server}
}

func NewPartialObliviousClient(s Suite, server *PublicKey) PartialObliviousClient {
	p, ok := s.(params)
	if !ok || server == nil {
		panic(ErrNoKey)
	}
	p.m = PartialObliviousMode

	return PartialObliviousClient{client{p}, server}
}

func NewServer(s Suite, key *PrivateKey) Server {
	p, ok := s.(params)
	if !ok || key == nil {
		panic(ErrNoKey)
	}
	p.m = BaseMode

	return Server{server{p, key}}
}

func NewVerifiableServer(s Suite, key *PrivateKey) VerifiableServer {
	p, ok := s.(params)
	if !ok || key == nil {
		panic(ErrNoKey)
	}
	p.m = VerifiableMode

	return VerifiableServer{server{p, key}}
}

func NewPartialObliviousServer(s Suite, key *PrivateKey) PartialObliviousServer {
	p, ok := s.(params)
	if !ok || key == nil {
		panic(ErrNoKey)
	}
	p.m = PartialObliviousMode

	return PartialObliviousServer{server{p, key}}
}

type params struct {
	m          Mode
	group      group.Group
	hash       crypto.Hash
	identifier string
}

func (p params) cannotBeImplementedExternally() {}

func (p params) String() string     { return p.Identifier() }
func (p params) Group() group.Group { return p.group }
func (p params) Hash() crypto.Hash  { return p.hash }
func (p params) Identifier() string { return p.identifier }

func (p params) getDST(name string) []byte {
	return append(append(append(append(
		[]byte{},
		[]byte(name)...),
		[]byte(version)...),
		[]byte{p.m, byte('-')}...),
		[]byte(p.identifier)...)
}

func (p params) scalarFromInfo(info []byte) (group.Scalar, error) {
	if len(info) > math.MaxUint16 {
		return nil, ErrInvalidInfo
	}
	lenInfo := []byte{0, 0}
	binary.BigEndian.PutUint16(lenInfo, uint16(len(info)))
	framedInfo := append(append(append([]byte{},
		[]byte(infoLabel)...),
		lenInfo...),
		info...)

	return p.group.HashToScalar(framedInfo, p.getDST(hashToScalarDST)), nil
}

func (p params) finalizeHash(h hash.Hash, input, info, element []byte) []byte {
	h.Reset()
	lenBuf := []byte{0, 0}

	binary.BigEndian.PutUint16(lenBuf, uint16(len(input)))
	mustWrite(h, lenBuf)
	mustWrite(h, input)

	if p.m == PartialObliviousMode {
		binary.BigEndian.PutUint16(lenBuf, uint16(len(info)))
		mustWrite(h, lenBuf)
		mustWrite(h, info)
	}

	binary.BigEndian.PutUint16(lenBuf, uint16(len(element)))
	mustWrite(h, lenBuf)
	mustWrite(h, element)

	mustWrite(h, []byte(finalizeDST))

	return h.Sum(nil)
}

func (p params) getDLEQParams() (out dleq.Params) {
	out.G = p.group
	out.H = p.hash
	out.DST = p.getDST("")

	return
}

func mustWrite(h io.Writer, bytes []byte) {
	bytesLen, err := h.Write(bytes)
	if err != nil {
		panic(err)
	}
	if len(bytes) != bytesLen {
		panic("failed to write")
	}
}

var (
	ErrInvalidSuite       = errors.New("invalid suite")
	ErrInvalidMode        = errors.New("invalid mode")
	ErrDeriveKeyPairError = errors.New("key pair derivation failed")
	ErrInvalidInput       = errors.New("invalid input")
	ErrInvalidInfo        = errors.New("invalid info")
	ErrInvalidProof       = errors.New("proof verification failed")
	ErrInverseZero        = errors.New("inverting a zero value")
	ErrNoKey              = errors.New("must provide a key")
)

type (
	Blind     = group.Scalar
	Blinded   = group.Element
	Evaluated = group.Element
)

// FinalizeData encapsulates data needed for Finalize step.
type FinalizeData struct {
	inputs  [][]byte
	blinds  []Blind
	evalReq *EvaluationRequest
}

// CopyBlinds copies the serialized blinds to use when determinstically
// invoking DeterministicBlind.
func (f FinalizeData) CopyBlinds() []Blind {
	out := make([]Blind, len(f.blinds))
	for i, b := range f.blinds {
		out[i] = b.Copy()
	}
	return out
}

// EvaluationRequest contains the blinded elements to be evaluated by the Server.
type EvaluationRequest struct {
	Elements []Blinded
}

// Evaluation contains a list of elements produced during server's evaluation, and
// for verifiable modes it also includes a proof.
type Evaluation struct {
	Elements []Evaluated
	Proof    *dleq.Proof
}
