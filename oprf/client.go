package oprf

import (
	"crypto/rand"
	"math"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/zk/dleq"
)

type client struct{ params }

type Client struct {
	client
}

type VerifiableClient struct {
	client
	pkS *PublicKey
}

type PartialObliviousClient struct {
	client
	pkS *PublicKey
}

func (c client) Blind(inputs [][]byte) (*FinalizeData, *EvaluationRequest, error) {
	if len(inputs) == 0 {
		return nil, nil, ErrInvalidInput
	}

	blinds := make([]Blind, len(inputs))
	for i := range inputs {
		blinds[i] = c.params.group.RandomScalar(rand.Reader)
	}

	return c.blind(inputs, blinds)
}

func (c client) DeterministicBlind(inputs [][]byte, blinds []Blind) (*FinalizeData, *EvaluationRequest, error) {
	if len(inputs) == 0 {
		return nil, nil, ErrInvalidInput
	}
	if len(inputs) != len(blinds) {
		return nil, nil, ErrInvalidInput
	}

	return c.blind(inputs, blinds)
}

func (c client) blind(inputs [][]byte, blinds []Blind) (*FinalizeData, *EvaluationRequest, error) {
	blindedElements := make([]Blinded, len(inputs))
	dst := c.params.getDST(hashToGroupDST)
	for i := range inputs {
		// finalizeHash frames the input with I2OSP(len(input), 2), so an input
		// of 2^16 bytes or more silently wraps the length prefix. Reject it, as
		// scalarFromInfo already does for info.
		if len(inputs[i]) > math.MaxUint16 {
			return nil, nil, ErrInvalidInput
		}
		blind := blinds[i]
		if blind == nil || *blind.Group().Params() != *c.params.group.Params() || blind.IsZero() {
			return nil, nil, ErrInvalidInput
		}

		point := c.params.group.HashToElement(inputs[i], dst)
		if point.IsIdentity() {
			return nil, nil, ErrInvalidInput
		}
		blindedElements[i] = c.params.group.NewElement().Mul(point, blind)
		if blindedElements[i].IsIdentity() {
			return nil, nil, ErrInvalidInput
		}
	}

	evalReq := &EvaluationRequest{blindedElements}
	finData := &FinalizeData{inputs, blinds, evalReq}

	return finData, evalReq, nil
}

func (c client) unblind(serUnblindeds [][]byte, blindeds []group.Element, blind []Blind) (err error) {
	invBlind := c.params.group.NewScalar()
	U := c.params.group.NewElement()

	for i := range blindeds {
		invBlind.Inv(blind[i])
		U.Mul(blindeds[i], invBlind)
		serUnblindeds[i], err = U.MarshalBinaryCompress()
		if err != nil {
			return err
		}
	}

	return nil
}

func (c client) validate(f *FinalizeData, e *Evaluation) (err error) {
	if f == nil || e == nil || f.evalReq == nil {
		return ErrInvalidInput
	}

	l := len(f.inputs)
	if l == 0 || len(f.blinds) != l || len(f.evalReq.Elements) != l || len(e.Elements) != l {
		return ErrInvalidInput
	}

	wantGroup := *c.params.group.Params()
	for i := range l {
		blind := f.blinds[i]
		blinded := f.evalReq.Elements[i]
		evaluated := e.Elements[i]
		if blind == nil || blinded == nil || evaluated == nil ||
			*blind.Group().Params() != wantGroup ||
			*blinded.Group().Params() != wantGroup ||
			*evaluated.Group().Params() != wantGroup ||
			blinded.IsIdentity() || evaluated.IsIdentity() {
			return ErrInvalidInput
		}
	}

	return nil
}

func (c client) finalize(f *FinalizeData, e *Evaluation, info []byte) ([][]byte, error) {
	unblindedElements := make([][]byte, len(f.blinds))
	err := c.unblind(unblindedElements, e.Elements, f.blinds)
	if err != nil {
		return nil, err
	}

	h := c.params.hash.New()
	outputs := make([][]byte, len(f.inputs))
	for i := range f.inputs {
		outputs[i] = c.params.finalizeHash(h, f.inputs[i], info, unblindedElements[i])
	}

	return outputs, nil
}

func (c Client) Finalize(f *FinalizeData, e *Evaluation) (outputs [][]byte, err error) {
	if err = c.validate(f, e); err != nil {
		return nil, err
	}

	return c.client.finalize(f, e, nil)
}

func (c VerifiableClient) Finalize(f *FinalizeData, e *Evaluation) (outputs [][]byte, err error) {
	if err := c.validate(f, e); err != nil {
		return nil, err
	}

	if !(dleq.Verifier{Params: c.getDLEQParams()}).VerifyBatchRFC9497(
		c.pkS.e,
		f.evalReq.Elements,
		e.Elements,
		e.Proof,
	) {
		return nil, ErrInvalidProof
	}

	return c.client.finalize(f, e, nil)
}

func (c PartialObliviousClient) Finalize(f *FinalizeData, e *Evaluation, info []byte) (outputs [][]byte, err error) {
	if err = c.validate(f, e); err != nil {
		return nil, err
	}

	tweakedKey, err := c.pointFromInfo(info)
	if err != nil {
		return nil, err
	}

	if !(dleq.Verifier{Params: c.getDLEQParams()}).VerifyBatchRFC9497(
		tweakedKey,
		e.Elements,
		f.evalReq.Elements,
		e.Proof,
	) {
		return nil, ErrInvalidProof
	}

	return c.client.finalize(f, e, info)
}

func (c PartialObliviousClient) pointFromInfo(info []byte) (group.Element, error) {
	m, err := c.params.scalarFromInfo(info)
	if err != nil {
		return nil, err
	}

	T := c.params.group.NewElement().MulGen(m)
	tweakedKey := c.params.group.NewElement().Add(T, c.pkS.e)
	if tweakedKey.IsIdentity() {
		return nil, ErrInvalidInfo
	}

	return tweakedKey, nil
}
