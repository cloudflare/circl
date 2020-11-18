package oprf

import (
	"crypto/rand"
	"errors"
)

// Client is a representation of a Client during protocol execution.
type Client struct{ suite }

// ClientRequest is a structure to encapsulate the output of a Request call.
type ClientRequest struct {
	inputs          [][]byte
	blinds          []Blind
	BlindedElements []Blinded
}

// NewClient creates a new instantiation of a Client.
func NewClient(id SuiteID) (*Client, error) {
   // base mode
}

func NewVerifiableClient(id SuiteID, pks *PublicKey) (*Client, error) {
   // verifiable mode
}
	suite, err := suiteFromID(id, m)
	if err != nil {
		return nil, err
	}

	return &Client{*suite}, nil
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
	var err error
	blindedElements := make([]Blinded, len(inputs))
	for i := range inputs {
		p := c.suite.Group.HashToElement(inputs[i], c.suite.getDST(hashToGroupDST))
		blindedElements[i], err = c.scalarMult(p, blinds[i])
		if err != nil {
			return nil, err
		}
	}
	return &ClientRequest{inputs, blinds, blindedElements}, nil
}

// Finalize computes the signed token from the server Evaluation and returns
// the output of the OPRF protocol. The function uses server's public key
// to verify the proof in verifiable mode.
func (c *Client) Finalize(r *ClientRequest, e *Evaluation, info []byte, pkS *PublicKey) ([][]byte, error) {
	l := len(r.blinds)
	if len(r.BlindedElements) != l || len(e.Elements) != l {
		return nil, errors.New("mismatch number of elements")
	}

	if c.Mode == VerifiableMode {
		if pkS == nil {
			return nil, errors.New("no public key provided")
		}
		if !c.verifyProof(r.BlindedElements, e, pkS) {
			return nil, errors.New("invalid proof")
		}
	}

	unblindedElements, err := c.unblind(e.Elements, r.blinds)
	if err != nil {
		return nil, err
	}
	outputs := make([][]byte, l)
	for i := 0; i < l; i++ {
		outputs[i] = c.finalizeHash(r.inputs[i], unblindedElements[i], info)
	}
	return outputs, nil
}

func (c *Client) verifyProof(blinds []Blinded, e *Evaluation, pkS *PublicKey) bool {
	pkSm, err := pkS.Serialize()
	if err != nil {
		return false
	}
	a0, a1, err := c.computeComposites(pkSm, blinds, e.Elements, nil)
	if err != nil {
		return false
	}
	M := c.suite.Group.NewElement()
	err = M.UnmarshalBinary(a0)
	if err != nil {
		return false
	}
	Z := c.suite.Group.NewElement()
	err = Z.UnmarshalBinary(a1)
	if err != nil {
		return false
	}

	sG := c.suite.Group.NewElement()
	ss := c.suite.Group.NewScalar()
	err = ss.UnmarshalBinary(e.Proof.S)
	if err != nil {
		return false
	}
	sG.MulGen(ss)

	cP := c.suite.Group.NewElement()
	cc := c.suite.Group.NewScalar()
	err = cc.UnmarshalBinary(e.Proof.C)
	if err != nil {
		return false
	}
	cP.Mul(pkS.Element, cc)
	sG.Add(sG, cP)
	a2, err := sG.MarshalBinary()
	if err != nil {
		return false
	}

	sM := c.suite.Group.NewElement()
	sM.Mul(M, ss)
	cZ := c.suite.Group.NewElement()
	cZ.Mul(Z, cc)
	sM.Add(sM, cZ)
	a3, err := sM.MarshalBinary()
	if err != nil {
		return false
	}

	gotC := c.doChallenge([5][]byte{pkSm, a0, a1, a2, a3})
	return gotC.IsEqual(cc)
}

func (c *Client) unblind(e []SerializedElement, blinds []Blind) ([][]byte, error) {
	unblindedElements := make([][]byte, len(e))
	p := c.Group.NewElement()
	invBlind := c.Group.NewScalar()
	for i := range e {
		err := p.UnmarshalBinary(e[i])
		if err != nil {
			return nil, err
		}
		invBlind.Inv(blinds[i])
		unblindedElements[i], err = c.scalarMult(p, invBlind)
		if err != nil {
			return nil, err
		}
	}
	return unblindedElements, nil
}
