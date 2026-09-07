package ecmr

import (
	"io"

	"github.com/cloudflare/circl/group"
)

type Client struct{}

func NewClient() *Client {
	return &Client{}
}

// Provision generates a new client key pair and computes the shared point
// with the server's public key.
func (c *Client) Provision(serverPub *PublicKey, rnd io.Reader) (*ProvisionResult, error) {
	if serverPub == nil || serverPub.element == nil {
		return nil, ErrNilKey
	}
	if rnd == nil {
		return nil, ErrNilReader
	}

	clientScalar := group.P521.RandomNonZeroScalar(rnd)

	clientPub := group.P521.NewElement().MulGen(clientScalar)
	clientPubBytes, err := clientPub.MarshalBinary()
	if err != nil {
		return nil, ErrMalformedPoint
	}

	sharedPoint := group.P521.NewElement().Mul(serverPub.element, clientScalar)
	sharedPointBytes, err := sharedPoint.MarshalBinary()
	if err != nil {
		return nil, ErrMalformedPoint
	}

	zeroScalar(clientScalar)

	return &ProvisionResult{
		ClientPublic: clientPubBytes,
		SharedPoint:  sharedPointBytes,
	}, nil
}

// CreateRecoveryRequest creates a blinded recovery request using the stored
// client public key and a fresh ephemeral scalar.
func (c *Client) CreateRecoveryRequest(
	clientPublicBytes []byte,
	serverPub *PublicKey,
	rnd io.Reader,
) (*RecoveryRequest, *RecoveryState, error) {
	if serverPub == nil || serverPub.element == nil {
		return nil, nil, ErrNilKey
	}
	if rnd == nil {
		return nil, nil, ErrNilReader
	}

	if len(clientPublicBytes) != PublicKeySize {
		return nil, nil, ErrMalformedPoint
	}

	clientPub := group.P521.NewElement()
	if err := clientPub.UnmarshalBinary(clientPublicBytes); err != nil {
		return nil, nil, ErrMalformedPoint
	}
	if clientPub.IsIdentity() {
		return nil, nil, ErrIdentityPoint
	}

	ephemeral := group.P521.RandomNonZeroScalar(rnd)

	ephemeralPub := group.P521.NewElement().MulGen(ephemeral)

	blindedPoint := group.P521.NewElement().Add(clientPub, ephemeralPub)
	blindedPointBytes, err := blindedPoint.MarshalBinary()
	if err != nil {
		zeroScalar(ephemeral)
		return nil, nil, ErrMalformedPoint
	}

	state := &RecoveryState{
		ephemeral: ephemeral,
		serverPub: group.P521.NewElement().Set(serverPub.element),
	}

	return &RecoveryRequest{BlindedPoint: blindedPointBytes}, state, nil
}

// RecoverKey completes key recovery using the server's response.
// After calling this function, the RecoveryState is invalidated.
func (c *Client) RecoverKey(
	state *RecoveryState,
	response *RecoveryResponse,
) ([]byte, error) {
	if state == nil || state.ephemeral == nil || state.serverPub == nil {
		return nil, ErrNilKey
	}

	defer func() {
		zeroScalar(state.ephemeral)
		state.ephemeral = nil
		state.serverPub = nil
	}()

	if response == nil || len(response.ProcessedPoint) != SharedPointSize {
		return nil, ErrMalformedPoint
	}

	serverResponse := group.P521.NewElement()
	if err := serverResponse.UnmarshalBinary(response.ProcessedPoint); err != nil {
		return nil, ErrMalformedPoint
	}
	if serverResponse.IsIdentity() {
		return nil, ErrIdentityPoint
	}

	blindingFactor := group.P521.NewElement().Mul(state.serverPub, state.ephemeral)

	negBlindingFactor := group.P521.NewElement().Neg(blindingFactor)
	sharedPoint := group.P521.NewElement().Add(serverResponse, negBlindingFactor)

	sharedPointBytes, err := sharedPoint.MarshalBinary()
	if err != nil {
		return nil, ErrMalformedPoint
	}

	return sharedPointBytes, nil
}

func zeroScalar(s group.Scalar) {
	if s != nil {
		s.SetUint64(0)
	}
}
