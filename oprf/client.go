package oprf

import (
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/group"
)

// Client is a representation of a OPRF client during protocol execution.
type Client struct {
	suite
	pkS *PublicKey
}

// ClientRequest is a structure to encapsulate the output of a Request call.
type ClientRequest struct {
	inputs   [][]byte
	blinds   []Blind
	elements []group.Element
}

// BlindedElements returns the serialized blinded elements produced for the client request.
func (r ClientRequest) BlindedElements() [][]byte {
	var err error
	serializedBlinds := make([][]byte, len(r.elements))
	for i := range r.elements {
		serializedBlinds[i], err = r.elements[i].MarshalBinaryCompress()
		if err != nil {
			return nil
		}
	}
	return serializedBlinds
}

// NewClient creates a client in base mode.
func NewClient(id SuiteID) (*Client, error) {
	suite, err := suiteFromID(id, BaseMode)
	if err != nil {
		return nil, err
	}
	return &Client{*suite, nil}, nil
}

// NewVerifiableClient creates a client in verifiable mode. A server's public
// key must be provided.
func NewVerifiableClient(id SuiteID, pkS *PublicKey) (*Client, error) {
	suite, err := suiteFromID(id, VerifiableMode)
	if err != nil {
		return nil, err
	}
	if pkS == nil {
		return nil, errors.New("no public key was provided")
	} else if id != pkS.s { // Verifies key corresponds to SuiteID.
		return nil, errors.New("key doesn't match with suite")
	}
	return &Client{*suite, pkS}, nil
}

// Request generates a request for server passing an array of inputs to be
// evaluated by server.
func (c *Client) Request(inputs [][]byte) (*ClientRequest, error) {
	if len(inputs) == 0 {
		return nil, errors.New("few inputs")
	}

	blinds := make([]Blind, len(inputs))
	for i := range inputs {
		blinds[i] = c.suite.Group.RandomScalar(rand.Reader)
	}

	return c.blind(inputs, blinds)
}

func (c *Client) blind(inputs [][]byte, blinds []Blind) (*ClientRequest, error) {
	blindedElements := make([]group.Element, len(inputs))
	for i := range inputs {
		p := c.suite.Group.HashToElement(inputs[i], c.suite.getDST(hashToGroupDST))
		blindedElements[i] = c.suite.Group.NewElement()
		blindedElements[i].Mul(p, blinds[i])
	}
	return &ClientRequest{inputs, blinds, blindedElements}, nil
}

// Finalize computes the signed token from the server Evaluation and returns
// the output of the OPRF protocol. The function uses server's public key
// to verify the proof in verifiable mode.
func (c *Client) Finalize(r *ClientRequest, e *Evaluation) ([][]byte, error) {
	l := len(r.blinds)
	if len(r.elements) != l || len(e.Elements) != l {
		return nil, errors.New("mismatch number of elements")
	}

	evals := make([]group.Element, len(e.Elements))
	for i := range e.Elements {
		evals[i] = c.suite.Group.NewElement()
		evals[i].UnmarshalBinary(e.Elements[i])
	}

	if c.Mode == VerifiableMode {
		if !c.verifyProof(r.elements, evals, *e.Proof) {
			return nil, errors.New("invalid proof")
		}
	}

	unblindedElements, err := c.unblind(evals, r.blinds)
	if err != nil {
		return nil, err
	}
	outputs := make([][]byte, l)
	for i := 0; i < l; i++ {
		outputs[i] = c.finalizeHash(r.inputs[i], unblindedElements[i])
	}
	return outputs, nil
}

func (c *Client) verifyProof(blinds []group.Element, elements []group.Element, proof Proof) bool {
	pkSm, err := c.pkS.Serialize()
	if err != nil {
		return false
	}

	M, Z, err := c.computeComposites(nil, c.pkS.e, blinds, elements)
	if err != nil {
		return false
	}

	a0, err := M.MarshalBinaryCompress()
	if err != nil {
		return false
	}
	a1, err := Z.MarshalBinaryCompress()
	if err != nil {
		return false
	}

	sG := c.suite.Group.NewElement()
	ss := c.suite.Group.NewScalar()
	err = ss.UnmarshalBinary(proof.S)
	if err != nil {
		return false
	}
	sG.MulGen(ss)

	cP := c.suite.Group.NewElement()
	cc := c.suite.Group.NewScalar()
	err = cc.UnmarshalBinary(proof.C)
	if err != nil {
		return false
	}
	cP.Mul(c.pkS.e, cc)
	sG.Add(sG, cP)
	a2, err := sG.MarshalBinaryCompress()
	if err != nil {
		return false
	}

	sM := c.suite.Group.NewElement()
	sM.Mul(M, ss)
	cZ := c.suite.Group.NewElement()
	cZ.Mul(Z, cc)
	sM.Add(sM, cZ)
	a3, err := sM.MarshalBinaryCompress()
	if err != nil {
		return false
	}

	gotC := c.doChallenge([5][]byte{pkSm, a0, a1, a2, a3})
	return gotC.IsEqual(cc)
}

func (c *Client) unblind(e []group.Element, blinds []Blind) ([][]byte, error) {
	var err error
	unblindedElements := make([][]byte, len(e))
	invBlind := c.Group.NewScalar()
	for i := range e {
		invBlind.Inv(blinds[i])
		unblindedElements[i], err = c.scalarMult(e[i], invBlind)
		if err != nil {
			return nil, err
		}
	}
	return unblindedElements, nil
}
