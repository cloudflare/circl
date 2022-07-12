package frost

import (
	"errors"
	"fmt"
)

type Combiner struct {
	Suite
	threshold  uint
	maxSigners uint
}

func NewCombiner(s Suite, threshold, maxSigners uint) (*Combiner, error) {
	if threshold > maxSigners {
		return nil, errors.New("frost: invalid parameters")
	}

	return &Combiner{Suite: s, threshold: threshold, maxSigners: maxSigners}, nil
}

func (c Combiner) CheckSignShares(
	signShares []*SignShare,
	pubKeySigners []*PublicKey,
	coms []*Commitment,
	pubKeyGroup *PublicKey,
	msg []byte,
) bool {
	if l := len(signShares); !(int(c.threshold) < l && l <= int(c.maxSigners)) {
		return false
	}
	if l := len(pubKeySigners); !(int(c.threshold) < l && l <= int(c.maxSigners)) {
		return false
	}
	if l := len(coms); !(int(c.threshold) < l && l <= int(c.maxSigners)) {
		return false
	}

	for i := range signShares {
		if !signShares[i].Verify(c.Suite, pubKeySigners[i], coms[i], coms, pubKeyGroup, msg) {
			return false
		}
	}

	return true
}

func (c Combiner) Sign(msg []byte, coms []*Commitment, signShares []*SignShare) ([]byte, error) {
	if l := len(coms); l <= int(c.threshold) {
		return nil, fmt.Errorf("frost: only %v shares of %v required", l, c.threshold)
	}

	bindingFactors, err := c.Suite.getBindingFactors(coms, msg)
	if err != nil {
		return nil, err
	}

	groupCom, err := c.Suite.getGroupCommitment(coms, bindingFactors)
	if err != nil {
		return nil, err
	}

	gcEnc, err := groupCom.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	z := c.Suite.g.NewScalar()
	for i := range signShares {
		z.Add(z, signShares[i].s.Value)
	}

	zEnc, err := z.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return append(append([]byte{}, gcEnc...), zEnc...), nil
}
