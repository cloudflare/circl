package frost

import (
	"fmt"
	"sort"

	"github.com/cloudflare/circl/group"
)

type Nonce struct {
	id      group.Scalar
	hiding  group.Scalar
	binding group.Scalar
}

func nonceGenerate(p params, randomBytes, secretEnc []byte) group.Scalar {
	return p.h3(append(append([]byte{}, randomBytes...), secretEnc...))
}

type Commitment struct {
	id      group.Scalar
	hiding  group.Element
	binding group.Element
}

func (c Commitment) MarshalBinary() ([]byte, error) {
	id, err := c.id.MarshalBinary()
	if err != nil {
		return nil, err
	}
	h, err := c.hiding.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}
	b, err := c.binding.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	return append(append(id, h...), b...), nil
}

func encodeCommitments(coms []Commitment) (out []byte, err error) {
	sort.SliceStable(coms, func(i, j int) bool {
		return coms[i].id.(fmt.Stringer).String() < coms[j].id.(fmt.Stringer).String()
	})

	for i := range coms {
		cEnc, err := coms[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		out = append(out, cEnc...)
	}
	return out, nil
}

type bindingFactor struct {
	ID     group.Scalar
	factor group.Scalar
}

func getBindingFactorFromID(bindingFactors []bindingFactor, id group.Scalar) (group.Scalar, error) {
	for i := range bindingFactors {
		if bindingFactors[i].ID.IsEqual(id) {
			return bindingFactors[i].factor, nil
		}
	}
	return nil, fmt.Errorf("frost: id not found")
}

func getBindingFactors(p params, msg []byte, groupPublicKey PublicKey, coms []Commitment) ([]bindingFactor, error) {
	groupPublicKeyEnc, err := groupPublicKey.key.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	msgHash := p.h4(msg)
	encodeComs, err := encodeCommitments(coms)
	if err != nil {
		return nil, err
	}
	encodeComsHash := p.h5(encodeComs)
	rhoInputPrefix := append(append(groupPublicKeyEnc, msgHash...), encodeComsHash...)

	bindingFactors := make([]bindingFactor, len(coms))
	for i := range coms {
		id, err := coms[i].id.MarshalBinary()
		if err != nil {
			return nil, err
		}
		rhoInput := append(append([]byte{}, rhoInputPrefix...), id...)
		bf := p.h1(rhoInput)
		bindingFactors[i] = bindingFactor{ID: coms[i].id, factor: bf}
	}

	return bindingFactors, nil
}

func getGroupCommitment(g group.Group, coms []Commitment, bindingFactors []bindingFactor) (group.Element, error) {
	gc := g.NewElement()
	tmp := g.NewElement()
	for i := range coms {
		bf, err := getBindingFactorFromID(bindingFactors, coms[i].id)
		if err != nil {
			return nil, err
		}
		tmp.Mul(coms[i].binding, bf)
		tmp.Add(tmp, coms[i].hiding)
		gc.Add(gc, tmp)
	}

	return gc, nil
}

func getChallenge(p params, groupCom group.Element, msg []byte, pubKey PublicKey) (group.Scalar, error) {
	gcEnc, err := groupCom.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}
	pkEnc, err := pubKey.key.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}
	chInput := append(append(append([]byte{}, gcEnc...), pkEnc...), msg...)

	return p.h2(chInput), nil
}
