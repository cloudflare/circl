package frost

import (
	"fmt"
	"io"
	"sort"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/math/polynomial"
	"github.com/cloudflare/circl/secretsharing"
)

type PeerSigner struct {
	Suite
	threshold      uint16
	maxSigners     uint16
	keyShare       secretsharing.Share
	myPublicKey    *PublicKey
	groupPublicKey PublicKey
}

func (p *PeerSigner) Commit(rnd io.Reader) (*Nonce, *Commitment, error) {
	var hidingNonceRandomness [32]byte
	_, err := io.ReadFull(rnd, hidingNonceRandomness[:])
	if err != nil {
		return nil, nil, err
	}

	var bindingNonceRandomness [32]byte
	_, err = io.ReadFull(rnd, bindingNonceRandomness[:])
	if err != nil {
		return nil, nil, err
	}

	return p.commitWithRandomness(hidingNonceRandomness[:], bindingNonceRandomness[:])
}

func (p *PeerSigner) commitWithRandomness(hidingNonceRnd, bindingNonceRnd []byte) (*Nonce, *Commitment, error) {
	secretEnc, err := p.keyShare.Value.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	pp := p.Suite.getParams()
	g := pp.group()
	hidingNonce := nonceGenerate(pp, hidingNonceRnd, secretEnc)
	hidingNonceCom := g.NewElement().MulGen(hidingNonce)

	bindingNonce := nonceGenerate(pp, bindingNonceRnd, secretEnc)
	bindingNonceCom := g.NewElement().MulGen(bindingNonce)

	return &Nonce{p.keyShare.ID, hidingNonce, bindingNonce},
		&Commitment{p.keyShare.ID, hidingNonceCom, bindingNonceCom},
		nil
}

func (p *PeerSigner) CheckKeyShare(c secretsharing.SecretCommitment) bool {
	return secretsharing.Verify(uint(p.threshold), p.keyShare, c)
}

func (p *PeerSigner) PublicKey() PublicKey {
	if p.myPublicKey == nil {
		g := p.Suite.getParams().group()
		p.myPublicKey = &PublicKey{p.Suite, g.NewElement().MulGen(p.keyShare.Value)}
	}

	return *p.myPublicKey
}

func (p *PeerSigner) Sign(msg []byte, pubKey PublicKey, nonce Nonce, coms []Commitment) (*SignShare, error) {
	if !p.keyShare.ID.IsEqual(nonce.id) {
		return nil, fmt.Errorf("frost: bad id")
	}

	pp := p.Suite.getParams()
	aux, err := common(pp, p.keyShare.ID, msg, pubKey, coms)
	if err != nil {
		return nil, err
	}

	g := pp.group()
	tmp := g.NewScalar().Mul(nonce.binding, aux.bindingFactor)
	signShare := g.NewScalar().Add(nonce.hiding, tmp)
	tmp.Mul(aux.lambdaID, p.keyShare.Value)
	tmp.Mul(tmp, aux.challenge)
	signShare.Add(signShare, tmp)

	return &SignShare{
		Suite: p.Suite,
		s:     secretsharing.Share{ID: p.keyShare.ID, Value: signShare},
	}, nil
}

type SignShare struct {
	Suite
	s secretsharing.Share
}

func (s SignShare) Verify(
	msg []byte,
	groupPublicKey PublicKey,
	pubKeySigner PublicKey,
	comSigner Commitment,
	coms []Commitment,
) bool {
	if s.s.ID != comSigner.id || s.s.ID.IsZero() {
		return false
	}

	pp := s.Suite.getParams()
	aux, err := common(pp, s.s.ID, msg, groupPublicKey, coms)
	if err != nil {
		return false
	}

	g := pp.group()
	comShare := g.NewElement().Mul(coms[aux.idx].binding, aux.bindingFactor)
	comShare.Add(comShare, coms[aux.idx].hiding)

	l := g.NewElement().MulGen(s.s.Value)
	r := g.NewElement().Mul(pubKeySigner.key, g.NewScalar().Mul(aux.challenge, aux.lambdaID))
	r.Add(r, comShare)

	return l.IsEqual(r)
}

type commonAux struct {
	idx           uint
	lambdaID      group.Scalar
	challenge     group.Scalar
	bindingFactor group.Scalar
}

func common(p params, id group.Scalar, msg []byte, groupPublicKey PublicKey, coms []Commitment) (aux *commonAux, err error) {
	if !sort.SliceIsSorted(coms,
		func(i, j int) bool {
			return coms[i].id.(fmt.Stringer).String() < coms[j].id.(fmt.Stringer).String()
		},
	) {
		return nil, fmt.Errorf("frost: commitments must be sorted")
	}

	idx := sort.Search(len(coms), func(j int) bool {
		return coms[j].id.(fmt.Stringer).String() >= id.(fmt.Stringer).String()
	})
	if !(idx < len(coms) && coms[idx].id.IsEqual(id)) {
		return nil, fmt.Errorf("frost: commitment not present")
	}

	bindingFactors, err := getBindingFactors(p, msg, groupPublicKey, coms)
	if err != nil {
		return nil, err
	}

	bindingFactor, err := getBindingFactorFromID(bindingFactors, id)
	if err != nil {
		return nil, err
	}

	g := p.group()
	groupCom, err := getGroupCommitment(g, coms, bindingFactors)
	if err != nil {
		return nil, err
	}

	challenge, err := getChallenge(p, groupCom, msg, groupPublicKey)
	if err != nil {
		return nil, err
	}

	peers := make([]group.Scalar, len(coms))
	for i := range coms {
		peers[i] = coms[i].id.Copy()
	}

	zero := g.NewScalar()
	lambdaID := polynomial.LagrangeBase(uint(idx), peers, zero)

	return &commonAux{
		idx:           uint(idx),
		lambdaID:      lambdaID,
		challenge:     challenge,
		bindingFactor: bindingFactor,
	}, nil
}
