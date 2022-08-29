package oprf

import (
	"crypto/rand"
	"crypto/subtle"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/zk/dleq"
)

type server struct {
	params
	privateKey *PrivateKey
}

type Server struct{ server }

type VerifiableServer struct{ server }

type PartialObliviousServer struct{ server }

func (s server) PublicKey() *PublicKey { return s.privateKey.Public() }

func (s server) evaluate(elements []Blinded, secret Blind) []Evaluated {
	evaluations := make([]Evaluated, len(elements))
	for i := range elements {
		evaluations[i] = s.params.group.NewElement().Mul(elements[i], secret)
	}

	return evaluations
}

func (s Server) Evaluate(req *EvaluationRequest) (*Evaluation, error) {
	evaluations := s.server.evaluate(req.Elements, s.privateKey.k)

	return &Evaluation{evaluations, nil}, nil
}

func (s VerifiableServer) Evaluate(req *EvaluationRequest) (*Evaluation, error) {
	evaluations := s.server.evaluate(req.Elements, s.privateKey.k)

	proof, err := dleq.Prover{Params: s.getDLEQParams()}.ProveBatch(
		s.privateKey.k,
		s.params.group.Generator(),
		s.PublicKey().e,
		req.Elements,
		evaluations,
		rand.Reader,
	)
	if err != nil {
		return nil, err
	}

	return &Evaluation{evaluations, proof}, nil
}

func (s PartialObliviousServer) Evaluate(req *EvaluationRequest, info []byte) (*Evaluation, error) {
	keyProof, evalSecret, err := s.secretFromInfo(info)
	if err != nil {
		return nil, err
	}

	evaluations := s.server.evaluate(req.Elements, evalSecret)

	proof, err := dleq.Prover{Params: s.getDLEQParams()}.ProveBatch(
		keyProof,
		s.params.group.Generator(),
		s.params.group.NewElement().MulGen(keyProof),
		evaluations,
		req.Elements,
		rand.Reader,
	)
	if err != nil {
		return nil, err
	}

	return &Evaluation{evaluations, proof}, nil
}

func (s server) secretFromInfo(info []byte) (t, tInv group.Scalar, err error) {
	m, err := s.params.scalarFromInfo(info)
	if err != nil {
		return nil, nil, err
	}
	t = s.params.group.NewScalar().Add(m, s.privateKey.k)

	if zero := s.params.group.NewScalar(); t.IsEqual(zero) {
		return nil, nil, ErrInverseZero
	}
	tInv = s.params.group.NewScalar().Inv(t)

	return t, tInv, nil
}

func (s server) fullEvaluate(input, info []byte) ([]byte, error) {
	evalSecret := s.privateKey.k
	if s.params.m == PartialObliviousMode {
		var err error
		_, evalSecret, err = s.secretFromInfo(info)
		if err != nil {
			return nil, err
		}
	}

	element := s.params.group.HashToElement(input, s.params.getDST(hashToGroupDST))
	evaluation := s.params.group.NewElement().Mul(element, evalSecret)
	serEval, err := evaluation.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	return s.finalizeHash(s.params.hash.New(), input, info, serEval), nil
}

func (s Server) FullEvaluate(input []byte) (output []byte, err error) {
	return s.fullEvaluate(input, nil)
}

func (s VerifiableServer) FullEvaluate(input []byte) (output []byte, err error) {
	return s.fullEvaluate(input, nil)
}

func (s PartialObliviousServer) FullEvaluate(input, info []byte) (output []byte, err error) {
	return s.fullEvaluate(input, info)
}

func (s server) verifyFinalize(input, info, expectedOutput []byte) bool {
	gotOutput, err := s.fullEvaluate(input, info)
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(gotOutput, expectedOutput) == 1
}

func (s Server) VerifyFinalize(input, expectedOutput []byte) bool {
	return s.verifyFinalize(input, nil, expectedOutput)
}

func (s VerifiableServer) VerifyFinalize(input, expectedOutput []byte) bool {
	return s.verifyFinalize(input, nil, expectedOutput)
}

func (s PartialObliviousServer) VerifyFinalize(input, info, expectedOutput []byte) bool {
	return s.verifyFinalize(input, info, expectedOutput)
}
