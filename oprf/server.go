package oprf

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"github.com/cloudflare/circl/group"
)

// Server is a representation of a OPRF server during protocol execution.
type Server struct {
	suite
	PrivateKey PrivateKey
}

// NewServer creates a Server in base mode, and generates a key if no skS is
// provided.
func NewServer(id SuiteID, skS *PrivateKey) (*Server, error) {
	return newServer(id, BaseMode, skS)
}

// NewVerifiableServer creates a Server in verifiable mode, and generates a
// key if no skS is provided.
func NewVerifiableServer(id SuiteID, skS *PrivateKey) (*Server, error) {
	return newServer(id, VerifiableMode, skS)
}

func newServer(id SuiteID, m Mode, skS *PrivateKey) (*Server, error) {
	suite, err := suiteFromID(id, m)
	if err != nil {
		return nil, err
	}
	if skS == nil {
		skS, err = GenerateKey(id, rand.Reader)
		if err != nil {
			return nil, err
		}
	} else if id != skS.s { // Verifies key corresponds to SuiteID.
		return nil, errors.New("key doesn't match with suite")
	}

	return &Server{*suite, *skS}, nil
}

// GetPublicKey returns the public key corresponding to the server.
func (s *Server) GetPublicKey() *PublicKey { return s.PrivateKey.Public() }

// Evaluate evaluates a set of blinded inputs from the client.
func (s *Server) Evaluate(blindedElements []Blinded, info []byte) (*Evaluation, error) {
	rr := s.suite.Group.RandomScalar(rand.Reader)
	return s.evaluateWithProofScalar(blindedElements, info, rr)
}

func (s *Server) evaluationContext(info []byte) []byte {
	lenBuf := []byte{0, 0}
	binary.BigEndian.PutUint16(lenBuf, uint16(len(info)))
	return append(append(s.getDST(contextDST), lenBuf...), info...)
}

// Evaluate evaluates a set of blinded inputs from the client using a fixed
// random scalar for proof generation
func (s *Server) evaluateWithProofScalar(blindedElements []Blinded, info []byte, proofScalar group.Scalar) (*Evaluation, error) {
	l := len(blindedElements)
	if l == 0 {
		return nil, errors.New("no elements to evaluate")
	}

	context := s.evaluationContext(info)
	m := s.Group.HashToScalar(context, s.getDST(hashToScalarDST))
	t := s.Group.NewScalar().Add(s.PrivateKey.k, m)
	tInv := s.Group.NewScalar().Inv(t)

	var err error
	input := make([]group.Element, l)
	eval := make([]group.Element, l)
	out := make([]SerializedElement, l)

	for i := range blindedElements {
		input[i] = s.suite.NewElement()
		err = input[i].UnmarshalBinary(blindedElements[i])
		if err != nil {
			return nil, err
		}

		eval[i] = s.Group.NewElement()
		eval[i].Mul(input[i], tInv)

		out[i], err = eval[i].MarshalBinaryCompress()
		if err != nil {
			return nil, err
		}
	}

	var proof *Proof
	if s.Mode == VerifiableMode {
		U := s.Group.NewElement().MulGen(t)
		proof, err = s.generateProofWithRandomScalar(t, s.Group.Generator(), U, eval, input, proofScalar)
		if err != nil {
			return nil, err
		}
	}

	return &Evaluation{out, proof}, nil
}

// FullEvaluate performs a full OPRF protocol at server-side.
func (s *Server) FullEvaluate(input, info []byte) ([]byte, error) {
	p := s.Group.HashToElement(input, s.getDST(hashToGroupDST))
	context := s.evaluationContext(info)
	m := s.Group.HashToScalar(context, s.getDST(hashToScalarDST))
	t := s.Group.NewScalar().Add(s.PrivateKey.k, m)
	tInv := s.Group.NewScalar().Inv(t)
	p.Mul(p, tInv)
	ser, err := p.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}
	return s.finalizeHash(input, info, ser), nil
}

// VerifyFinalize performs a full OPRF protocol and returns true if the output
// matches the expected output.
func (s *Server) VerifyFinalize(input, info, expectedOutput []byte) bool {
	gotOutput, err := s.FullEvaluate(input, info)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(gotOutput, expectedOutput) == 1
}

func (s *Server) generateProofWithRandomScalar(k group.Scalar, A, B group.Element, Cs []group.Element, Ds []group.Element, rr group.Scalar) (*Proof, error) {
	M, Z, err := s.computeComposites(k, B, Cs, Ds)
	if err != nil {
		return nil, err
	}

	Bm, err := B.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	a2e := s.Group.NewElement()
	a2e.Mul(A, rr)
	a2, err := a2e.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	a3e := s.Group.NewElement()
	a3e.Mul(M, rr)
	a3, err := a3e.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	a0, err := M.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}
	a1, err := Z.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	cc := s.doChallenge([5][]byte{Bm, a0, a1, a2, a3})
	ss := s.suite.Group.NewScalar()
	ss.Mul(cc, k)
	ss.Sub(rr, ss)

	serC, err := cc.MarshalBinary()
	if err != nil {
		return nil, err
	}
	serS, err := ss.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &Proof{serC, serS}, nil
}
