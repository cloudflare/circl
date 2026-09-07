package ecmr

import (
	"github.com/cloudflare/circl/group"
)

type Server struct {
	key *PrivateKey
}

func NewServer(key *PrivateKey) (*Server, error) {
	if key == nil || key.scalar == nil {
		return nil, ErrNilKey
	}
	return &Server{key: key}, nil
}

func (s *Server) PublicKey() *PublicKey {
	return s.key.Public()
}

// ProcessRecoveryRequest processes a client's recovery request and returns
// the server's response.
func (s *Server) ProcessRecoveryRequest(req *RecoveryRequest) (*RecoveryResponse, error) {
	if req == nil || len(req.BlindedPoint) != PublicKeySize {
		return nil, ErrMalformedPoint
	}

	blindedPoint := group.P521.NewElement()
	if err := blindedPoint.UnmarshalBinary(req.BlindedPoint); err != nil {
		return nil, ErrMalformedPoint
	}
	if blindedPoint.IsIdentity() {
		return nil, ErrIdentityPoint
	}

	response := group.P521.NewElement().Mul(blindedPoint, s.key.scalar)
	responseBytes, err := response.MarshalBinary()
	if err != nil {
		return nil, ErrMalformedPoint
	}

	return &RecoveryResponse{ProcessedPoint: responseBytes}, nil
}
