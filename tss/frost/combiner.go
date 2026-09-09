package frost

import "fmt"

type Coordinator struct {
	Suite
	threshold  uint
	maxSigners uint
}

func NewCoordinator(s Suite, threshold, maxSigners uint) (*Coordinator, error) {
	if threshold > maxSigners {
		return nil, fmt.Errorf("frost: invalid parameters")
	}

	return &Coordinator{Suite: s, threshold: threshold, maxSigners: maxSigners}, nil
}

func (c Coordinator) CheckSignShares(
	msg []byte,
	groupPublicKey PublicKey,
	signShares []SignShare,
	coms []Commitment,
	pubKeySigners []PublicKey,
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
		if !signShares[i].Verify(msg, groupPublicKey, pubKeySigners[i], coms[i], coms) {
			return false
		}
	}

	return true
}

func (c Coordinator) Aggregate(
	msg []byte,
	groupPublicKey PublicKey,
	signShares []SignShare,
	coms []Commitment,
) ([]byte, error) {
	if l := len(coms); l <= int(c.threshold) {
		return nil, fmt.Errorf("frost: only %v shares of %v required", l, c.threshold)
	}

	p := c.Suite.getParams()
	bindingFactors, err := getBindingFactors(p, msg, groupPublicKey, coms)
	if err != nil {
		return nil, err
	}

	g := p.group()
	groupCom, err := getGroupCommitment(g, coms, bindingFactors)
	if err != nil {
		return nil, err
	}

	gcEnc, err := groupCom.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	z := g.NewScalar()
	for i := range signShares {
		z.Add(z, signShares[i].s.Value)
	}

	zEnc, err := z.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return append(append([]byte{}, gcEnc...), zEnc...), nil
}
