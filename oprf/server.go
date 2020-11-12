package oprf

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
)

// Server is a representation of a Server during protocol execution.
type Server struct {
	suite
	Kp KeyPair
}

// NewServerWithKeyPair creates a new instantiation of a Server. It can create
// a server with existing keys or use pre-generated keys.
func NewServerWithKeyPair(id SuiteID, m Mode, kp KeyPair) (*Server, error) {
	// Verifies keypair corresponds to SuiteID.
	if id != kp.id {
		return nil, ErrUnsupportedSuite
	}

	suite, err := suiteFromID(id, m)
	if err != nil {
		return nil, err
	}

	return &Server{*suite, kp}, nil
}

// NewServer creates a new instantiation of a Server.
func NewServer(id SuiteID, m Mode) (*Server, error) {
	suite, err := suiteFromID(id, m)
	if err != nil {
		return nil, err
	}
	keyPair := suite.generateKeyPair()

	return &Server{*suite, *keyPair}, nil
}

// Evaluate blindly signs a client token.
func (s *Server) Evaluate(blindedElements []Blinded) (*Evaluation, error) {
	l := len(blindedElements)
	if l == 0 {
		return nil, errors.New("few elements")
	}

	var err error
	eval := make([]Serialized, l)
	p := s.suite.NewElement()

	for i := range blindedElements {
		err = p.UnmarshalBinary(blindedElements[i])
		if err != nil {
			return nil, err
		}

		eval[i], err = s.scalarMult(p, s.Kp.privateKey)
		if err != nil {
			return nil, err
		}
	}

	var proof *Proof
	if s.Mode == VerifiableMode {
		proof, err = s.generateProof(blindedElements, eval)
		if err != nil {
			return nil, err
		}
	}

	return &Evaluation{eval, proof}, nil
}

// FullEvaluate performs a full evaluation at the server side.
func (s *Server) FullEvaluate(input, info []byte) ([]byte, error) {
	dst := s.getDST(hashToGroupDST)
	H := s.Group.Hashes(dst)
	p := H.Hash(input)

	ser, err := s.scalarMult(p, s.Kp.privateKey)
	if err != nil {
		return nil, err
	}

	return s.finalizeHash(input, ser, info), nil
}

// VerifyFinalize verifies the evaluation.
func (s *Server) VerifyFinalize(input, info, output []byte) bool {
	gotOutput, err := s.FullEvaluate(input, info)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(gotOutput, output) == 1
}

func (s *Server) generateProof(b []Blinded, eval []Serialized) (*Proof, error) {
	pkSm, err := s.Kp.publicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	h2g := s.Group.Hashes(s.getDST(hashToGroupDST))
	rnd := s.suite.Group.Random()

	a0, a1, err := s.computeComposites(h2g, pkSm, b, eval, s.Kp.privateKey)
	if err != nil {
		return nil, err
	}
	M := s.Group.NewElement()
	err = M.UnmarshalBinary(a0)
	if err != nil {
		return nil, err
	}
	rr := rnd.RndScl(rand.Reader)

	a2e := s.Group.NewElement()
	a2e.MulGen(rr)
	a2, err := a2e.MarshalBinary()
	if err != nil {
		return nil, err
	}

	a3e := s.Group.NewElement()
	a3e.Mul(M, rr)
	a3, err := a3e.MarshalBinary()
	if err != nil {
		return nil, err
	}

	cc := s.doChallenge(h2g, [5][]byte{pkSm, a0, a1, a2, a3})
	ss := s.suite.Group.NewScalar()
	ss.Mul(cc, s.Kp.privateKey)
	ss.Sub(rr, ss)

	serC, err := cc.MarshalBinary()
	if err != nil {
		return nil, err
	}
	serS, err := ss.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &Proof{pkSm, serC, serS}, nil
}
