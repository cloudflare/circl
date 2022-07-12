package frost

import (
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/math/polynomial"
	"github.com/cloudflare/circl/secretsharing"
)

type PeerSigner struct {
	Suite
	threshold  uint16
	maxSigners uint16
	keyShare   secretsharing.Share
	myPubKey   *PublicKey
}

func (p PeerSigner) Commit(rnd io.Reader) (*Nonce, *Commitment, error) {
	hidingNonce, err := p.Suite.nonceGenerate(rnd, p.keyShare.Value)
	if err != nil {
		return nil, nil, err
	}
	bindingNonce, err := p.Suite.nonceGenerate(rnd, p.keyShare.Value)
	if err != nil {
		return nil, nil, err
	}

	return p.commitWithNonce(hidingNonce, bindingNonce)
}

func (p PeerSigner) commitWithNonce(hidingNonce, bindingNonce group.Scalar) (*Nonce, *Commitment, error) {
	hidingNonceCom := p.Suite.g.NewElement().MulGen(hidingNonce)
	bindingNonceCom := p.Suite.g.NewElement().MulGen(bindingNonce)
	return &Nonce{p.keyShare.ID, hidingNonce, bindingNonce}, &Commitment{p.keyShare.ID, hidingNonceCom, bindingNonceCom}, nil
}

func (p PeerSigner) CheckKeyShare(c secretsharing.SecretCommitment) bool {
	return secretsharing.Verify(uint(p.threshold), p.keyShare, c)
}

func (p PeerSigner) Public() *PublicKey {
	if p.myPubKey == nil {
		p.myPubKey = &PublicKey{p.Suite, p.Suite.g.NewElement().MulGen(p.keyShare.Value)}
	}
	return p.myPubKey
}

func (p PeerSigner) Sign(msg []byte, pubKey *PublicKey, nonce *Nonce, coms []*Commitment) (*SignShare, error) {
	if !p.keyShare.ID.IsEqual(nonce.ID) {
		return nil, errors.New("frost: bad id")
	}
	aux, err := p.Suite.common(p.keyShare.ID, msg, pubKey, coms)
	if err != nil {
		return nil, err
	}

	tmp := p.Suite.g.NewScalar().Mul(nonce.binding, aux.bindingFactor)
	signShare := p.Suite.g.NewScalar().Add(nonce.hiding, tmp)
	tmp.Mul(aux.lambdaID, p.keyShare.Value)
	tmp.Mul(tmp, aux.challenge)
	signShare.Add(signShare, tmp)

	return &SignShare{s: secretsharing.Share{
		ID:    p.keyShare.ID,
		Value: signShare,
	}}, nil
}

type SignShare struct {
	s secretsharing.Share
}

func (s *SignShare) Verify(
	suite Suite,
	pubKeySigner *PublicKey,
	comSigner *Commitment,
	coms []*Commitment,
	pubKeyGroup *PublicKey,
	msg []byte,
) bool {
	if s.s.ID != comSigner.ID || s.s.ID.IsZero() {
		return false
	}

	aux, err := suite.common(s.s.ID, msg, pubKeyGroup, coms)
	if err != nil {
		return false
	}

	comShare := suite.g.NewElement().Mul(coms[aux.idx].binding, aux.bindingFactor)
	comShare.Add(comShare, coms[aux.idx].hiding)

	l := suite.g.NewElement().MulGen(s.s.Value)
	r := suite.g.NewElement().Mul(pubKeySigner.key, suite.g.NewScalar().Mul(aux.challenge, aux.lambdaID))
	r.Add(r, comShare)

	return l.IsEqual(r)
}

type commonAux struct {
	idx           uint
	lambdaID      group.Scalar
	challenge     group.Scalar
	bindingFactor group.Scalar
}

func (s Suite) common(id group.Scalar, msg []byte, pubKey *PublicKey, coms []*Commitment) (aux *commonAux, err error) {
	if !sort.SliceIsSorted(coms,
		func(i, j int) bool {
			return coms[i].ID.(fmt.Stringer).String() < coms[j].ID.(fmt.Stringer).String()
		},
	) {
		return nil, errors.New("frost: commitments must be sorted")
	}

	idx := sort.Search(len(coms), func(j int) bool {
		return coms[j].ID.(fmt.Stringer).String() >= id.(fmt.Stringer).String()
	})
	if !(idx < len(coms) && coms[idx].ID.IsEqual(id)) {
		return nil, errors.New("frost: commitment not present")
	}

	bindingFactors, err := s.getBindingFactors(coms, msg)
	if err != nil {
		return nil, err
	}

	bindingFactor, err := s.getBindingFactorFromID(bindingFactors, id)
	if err != nil {
		return nil, err
	}

	groupCom, err := s.getGroupCommitment(coms, bindingFactors)
	if err != nil {
		return nil, err
	}

	challenge, err := s.getChallenge(groupCom, pubKey, msg)
	if err != nil {
		return nil, err
	}

	peers := make([]group.Scalar, len(coms))
	for i := range coms {
		peers[i] = coms[i].ID.Copy()
	}

	zero := s.g.NewScalar()
	lambdaID := polynomial.LagrangeBase(uint(idx), peers, zero)

	return &commonAux{
		idx:           uint(idx),
		lambdaID:      lambdaID,
		challenge:     challenge,
		bindingFactor: bindingFactor,
	}, nil
}
