package oprf

import (
	"crypto/rand"
	"encoding/binary"
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
	Inputs   [][]byte
	Blinds   []Blind
	Elements []group.Element
}

// BlindedElements returns the serialized blinded elements produced for the client request.
func (r ClientRequest) BlindedElements() [][]byte {
	var err error
	serializedBlinds := make([][]byte, len(r.Elements))
	for i := range r.Elements {
		serializedBlinds[i], err = r.Elements[i].MarshalBinaryCompress()
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
	c.blindMultiplicative(blindedElements, inputs, blinds)
	return &ClientRequest{inputs, blinds, blindedElements}, nil
}

func (c *Client) blindMultiplicative(blindedElt []group.Element, inputs [][]byte, blinds []Blind) {
	for i := range inputs {
		p := c.suite.Group.HashToElement(inputs[i], c.suite.getDST(hashToGroupDST))
		blindedElt[i] = c.suite.Group.NewElement()
		blindedElt[i].Mul(p, blinds[i])
	}
}

// Finalize computes the signed token from the server Evaluation and returns
// the output of the OPRF protocol. The function uses server's public key
// to verify the proof in verifiable mode.
func (c *Client) Finalize(r *ClientRequest, e *Evaluation, info []byte) ([][]byte, error) {
	l := len(r.Blinds)
	if len(r.Elements) != l || len(e.Elements) != l {
		return nil, errors.New("mismatch number of elements")
	}

	var err error
	evals := make([]group.Element, len(e.Elements))
	for i := range e.Elements {
		evals[i] = c.suite.Group.NewElement()
		err = evals[i].UnmarshalBinary(e.Elements[i])
		if err != nil {
			return nil, err
		}
	}

	if c.Mode == VerifiableMode {
		context := c.evaluationContext(info)
		m := c.Group.HashToScalar(context, c.getDST(hashToScalarDST))
		T := c.Group.NewElement().MulGen(m)
		U := c.Group.NewElement().Add(T, c.pkS.e)

		if !c.verifyProof(c.Group.Generator(), U, evals, r.Elements, e.Proof) {
			return nil, errors.New("invalid proof")
		}
	}

	unblindedElements, err := c.unblind(evals, r.Blinds)
	if err != nil {
		return nil, err
	}
	outputs := make([][]byte, l)
	for i := 0; i < l; i++ {
		outputs[i] = c.finalizeHash(r.Inputs[i], info, unblindedElements[i])
	}
	return outputs, nil
}

func (c *Client) verifyProof(A, B group.Element, Cs, Ds []group.Element, proof *Proof) bool {
	M, Z, err := c.computeComposites(nil, B, Cs, Ds)
	if err != nil {
		return false
	}

	ss := c.suite.Group.NewScalar()
	err = ss.UnmarshalBinary(proof.S)
	if err != nil {
		return false
	}

	cc := c.suite.Group.NewScalar()
	err = cc.UnmarshalBinary(proof.C)
	if err != nil {
		return false
	}

	sA := c.Group.NewElement().Mul(A, ss)
	cB := c.Group.NewElement().Mul(B, cc)
	t2 := c.Group.NewElement().Add(sA, cB)

	sM := c.Group.NewElement().Mul(M, ss)
	cZ := c.Group.NewElement().Mul(Z, cc)
	t3 := c.Group.NewElement().Add(sM, cZ)

	Bm, err := B.MarshalBinaryCompress()
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
	a2, err := t2.MarshalBinaryCompress()
	if err != nil {
		return false
	}
	a3, err := t3.MarshalBinaryCompress()
	if err != nil {
		return false
	}

	gotC := c.doChallenge([5][]byte{Bm, a0, a1, a2, a3})
	return gotC.IsEqual(cc)
}

func (c *Client) unblind(blindedElt []group.Element, blind []Blind) ([]UnBlinded, error) {
	return c.unblindMultiplicative(blindedElt, blind)
}

func (c *Client) evaluationContext(info []byte) []byte {
	lenBuf := []byte{0, 0}
	binary.BigEndian.PutUint16(lenBuf, uint16(len(info)))
	return append(append(c.getDST(contextDST), lenBuf...), info...)
}

func (c *Client) unblindMultiplicative(blindedElt []group.Element, blind []Blind) ([]UnBlinded, error) {
	var err error
	unblindedElt := make([]UnBlinded, len(blindedElt))
	invBlind := c.Group.NewScalar()
	U := c.Group.NewElement()

	for i := range blindedElt {
		invBlind.Inv(blind[i])
		U.Mul(blindedElt[i], invBlind)
		unblindedElt[i], err = U.MarshalBinaryCompress()
		if err != nil {
			return nil, err
		}
	}
	return unblindedElt, err
}
