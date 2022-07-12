package frost

import (
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/cloudflare/circl/group"
)

type Nonce struct {
	ID              group.Scalar
	hiding, binding group.Scalar
}

func (s Suite) nonceGenerate(rnd io.Reader, secret group.Scalar) (group.Scalar, error) {
	randomBytes := make([]byte, 32)
	_, err := io.ReadFull(rnd, randomBytes)
	if err != nil {
		return nil, err
	}
	secretEnc, err := secret.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return s.hasher.h3(append(randomBytes, secretEnc...)), nil
}

type Commitment struct {
	ID              group.Scalar
	hiding, binding group.Element
}

func (c Commitment) MarshalBinary() ([]byte, error) {
	id, err := c.ID.MarshalBinary()
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

func encodeCommitments(coms []*Commitment) ([]byte, error) {
	sort.SliceStable(coms, func(i, j int) bool {
		return coms[i].ID.(fmt.Stringer).String() < coms[j].ID.(fmt.Stringer).String()
	})

	var out []byte
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

func (s Suite) getBindingFactorFromID(bindingFactors []bindingFactor, id group.Scalar) (group.Scalar, error) {
	for i := range bindingFactors {
		if bindingFactors[i].ID.IsEqual(id) {
			return bindingFactors[i].factor, nil
		}
	}
	return nil, errors.New("frost: id not found")
}

func (s Suite) getBindingFactors(coms []*Commitment, msg []byte) ([]bindingFactor, error) {
	msgHash := s.hasher.h4(msg)
	encodeComs, err := encodeCommitments(coms)
	if err != nil {
		return nil, err
	}
	encodeComsHash := s.hasher.h5(encodeComs)
	rhoInputPrefix := append(msgHash, encodeComsHash...)

	bindingFactors := make([]bindingFactor, len(coms))
	for i := range coms {
		id, err := coms[i].ID.MarshalBinary()
		if err != nil {
			return nil, err
		}
		rhoInput := append(append([]byte{}, rhoInputPrefix...), id...)
		bf := s.hasher.h1(rhoInput)
		bindingFactors[i] = bindingFactor{ID: coms[i].ID, factor: bf}
	}

	return bindingFactors, nil
}

func (s Suite) getGroupCommitment(coms []*Commitment, bindingFactors []bindingFactor) (group.Element, error) {
	gc := s.g.NewElement()
	tmp := s.g.NewElement()
	for i := range coms {
		bf, err := s.getBindingFactorFromID(bindingFactors, coms[i].ID)
		if err != nil {
			return nil, err
		}
		tmp.Mul(coms[i].binding, bf)
		tmp.Add(tmp, coms[i].hiding)
		gc.Add(gc, tmp)
	}

	return gc, nil
}

func (s Suite) getChallenge(groupCom group.Element, pubKey *PublicKey, msg []byte) (group.Scalar, error) {
	gcEnc, err := groupCom.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}
	pkEnc, err := pubKey.key.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}
	chInput := append(append(append([]byte{}, gcEnc...), pkEnc...), msg...)

	return s.hasher.h2(chInput), nil
}
