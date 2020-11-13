package oprf

import (
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/group"
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
func NewClient(id SuiteID, m Mode) (*Client, error) {
	suite, err := suiteFromID(id, m)
	if err != nil {
		return nil, err
	}

	return &Client{*suite}, nil
}

// Request generates a token and its blinded version.
func (c *Client) Request(inputs [][]byte) (*ClientRequest, error) {
	if len(inputs) == 0 {
		return nil, errors.New("few inputs")
	}

	rnd := c.suite.Group.Random()
	blinds := make([]Blind, len(inputs))
	for i := range inputs {
		blinds[i] = rnd.RandomScalar(rand.Reader)
	}

	h2g := c.suite.Group.Hashes(c.getDST(hashToGroupDST))
	return c.blind(h2g, inputs, blinds)
}

func (c *Client) blind(h2g group.Hasher, inputs [][]byte, blinds []Blind) (*ClientRequest, error) {
	var err error
	blindedElements := make([]Blinded, len(inputs))
	for i := range inputs {
		p := h2g.HashToElement(inputs[i])
		blindedElements[i], err = c.scalarMult(p, blinds[i])
		if err != nil {
			return nil, err
		}
	}
	return &ClientRequest{inputs, blinds, blindedElements}, nil
}

// Finalize computes the signed token from the server Evaluation and returns
// the output of the OPRF protocol.
func (c *Client) Finalize(r *ClientRequest, e *Evaluation, info []byte) ([][]byte, error) {
	l := len(r.blinds)
	if len(r.BlindedElements) != l || len(e.Elements) != l {
		return nil, errors.New("mismatch number of elements")
	}

	if c.Mode == VerifiableMode {
		if !c.verifyProof(r.BlindedElements, e) {
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

func (c *Client) verifyProof(blinds []Blinded, e *Evaluation) bool {
	h2g := c.suite.Group.Hashes(c.getDST(hashToGroupDST))
	pkSm := e.Proof.PublicKey
	a0, a1, err := c.computeComposites(h2g, pkSm, blinds, e.Elements, nil)
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
	pkS := c.suite.Group.NewElement()
	err = pkS.UnmarshalBinary(pkSm)
	if err != nil {
		return false
	}
	cP.Mul(pkS, cc)
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

	gotC := c.doChallenge(h2g, [5][]byte{pkSm, a0, a1, a2, a3})
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
