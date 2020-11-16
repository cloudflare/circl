package oprf

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
)

// Server is a representation of a Server during protocol execution.
type Server struct {
	suite
	privateKey PrivateKey
}

// NewServerWithKey creates a new instantiation of a Server. It can create
// a server with existing keys or use pre-generated keys.
func NewServerWithKey(id SuiteID, m Mode, skS *PrivateKey) (*Server, error) {
	// Verifies keypair corresponds to SuiteID.
	if id != skS.SuiteID {
		return nil, errors.New("keys don't match with suite")
	}

	suite, err := suiteFromID(id, m)
	if err != nil {
		return nil, err
	}

	return &Server{*suite, *skS}, nil
}

// NewServer creates a new instantiation of a Server.
func NewServer(id SuiteID, m Mode) (*Server, error) {
	suite, err := suiteFromID(id, m)
	if err != nil {
		return nil, err
	}
	skS := suite.generateKey()

	return &Server{*suite, *skS}, nil
}

func (s *Server) GetPublicKey() *PublicKey { return s.privateKey.Public() }

// Evaluate evaluates a set of blinded inputs from the client.
func (s *Server) Evaluate(blindedElements []Blinded) (*Evaluation, error) {
	l := len(blindedElements)
	if l == 0 {
		return nil, errors.New("few elements")
	}

	var err error
	eval := make([]SerializedElement, l)
	p := s.suite.NewElement()

	for i := range blindedElements {
		err = p.UnmarshalBinary(blindedElements[i])
		if err != nil {
			return nil, err
		}
		eval[i], err = s.scalarMult(p, s.privateKey.Scalar)
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
	p := s.Group.HashToElement(input, s.getDST(hashToGroupDST))

	ser, err := s.scalarMult(p, s.privateKey.Scalar)
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

func (s *Server) generateProof(b []Blinded, eval []SerializedElement) (*Proof, error) {
	pkS := s.privateKey.Public()
	pkSm, err := pkS.Serialize()
	if err != nil {
		return nil, err
	}

	a0, a1, err := s.computeComposites(pkSm, b, eval, s.privateKey.Scalar)
	if err != nil {
		return nil, err
	}
	M := s.Group.NewElement()
	err = M.UnmarshalBinary(a0)
	if err != nil {
		return nil, err
	}
	rr := s.suite.Group.RandomScalar(rand.Reader)

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

	cc := s.doChallenge([5][]byte{pkSm, a0, a1, a2, a3})
	ss := s.suite.Group.NewScalar()
	ss.Mul(cc, s.privateKey.Scalar)
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
