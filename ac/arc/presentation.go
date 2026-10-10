package arc

import (
	"crypto/rand"
	"io"
	"math"
	"math/big"
	"slices"

	"github.com/cloudflare/circl/internal/conv"
	"golang.org/x/crypto/cryptobyte"
)

type nonceSet struct {
	limit     big.Int
	bitField  big.Int
	available uint16
}

func newNonceSet(limit uint16) (n nonceSet) {
	n.available = limit
	n.limit.SetUint64(uint64(limit))
	n.bitField.SetUint64(1)
	n.bitField.Lsh(&n.bitField, uint(limit))
	return
}

func (n *nonceSet) AddRandom(rnd io.Reader) uint16 {
	for {
		chosen, _ := rand.Int(rnd, &n.limit)
		x := chosen.Uint64()
		if n.bitField.Bit(int(x)) == 0 {
			n.bitField.SetBit(&n.bitField, int(x), 1)
			n.available -= 1
			return uint16(x)
		}
	}
}

func (n *nonceSet) Marshal(b *cryptobyte.Builder) error {
	limit := n.limit.Uint64()
	data := make([]byte, (limit+1+7)/8)
	n.bitField.FillBytes(data)
	b.AddUint64(limit)
	b.AddUint16(n.available)
	b.AddBytes(data)
	return nil
}

func (n *nonceSet) Unmarshal(s *cryptobyte.String) bool {
	var limit uint64
	if !s.ReadUint64(&limit) || limit == 0 || limit >= math.MaxUint16 {
		return false
	}

	var available uint16
	data := make([]byte, (limit+1+7)/8)
	if !s.ReadUint16(&available) || !s.CopyBytes(data) {
		return false
	}

	n.limit.SetUint64(limit)
	n.available = available
	n.bitField.SetBytes(data)
	return true
}

type Presentation struct {
	u, uPrimeCom, m1Com, tag elt
	proof                    presProof
	ID                       SuiteID
}

func (p Presentation) String() string {
	return printAny(p.u, p.uPrimeCom, p.m1Com, p.tag, proof(p.proof))
}

func (p *Presentation) UnmarshalBinary(b []byte) error {
	return conv.UnmarshalBinary(p, b)
}

func (p *Presentation) MarshalBinary() ([]byte, error) {
	return conv.MarshalBinary(p)
}

func (p *Presentation) Marshal(b *cryptobyte.Builder) error {
	return conv.MarshalSlice(b,
		eltCom{p.u}, eltCom{p.uPrimeCom}, eltCom{p.m1Com}, eltCom{p.tag},
		proof(p.proof))
}

func (p *Presentation) Unmarshal(s *cryptobyte.String) bool {
	suite := p.ID.getSuite()
	suite.initElt(&p.u, &p.uPrimeCom, &p.m1Com, &p.tag)
	p.proof.init(suite)
	return conv.UnmarshalSlice(s, eltCom{p.u}, eltCom{p.uPrimeCom},
		eltCom{p.m1Com}, eltCom{p.tag}, proof(p.proof))
}

func (p *Presentation) IsEqual(q *Presentation) bool {
	return p.ID == q.ID && slices.EqualFunc(
		[]elt{p.u, p.uPrimeCom, p.m1Com, p.tag},
		[]elt{q.u, q.uPrimeCom, q.m1Com, q.tag},
		elt.IsEqual,
	) && proof(p.proof).IsEqual(proof(q.proof))
}

type State struct {
	presCtx []byte
	cred    Credential
	nonce   nonceSet
	ID      SuiteID
}

func NewState(cred *Credential, presCtx []byte, limit uint16) (*State, error) {
	if limit == 0 {
		return nil, ErrLimitValid
	}

	if len(presCtx) >= math.MaxUint16 {
		return nil, ErrContextLength
	}

	return &State{
		ID:      cred.ID,
		cred:    *cred,
		presCtx: presCtx,
		nonce:   newNonceSet(limit),
	}, nil
}

func (s *State) UnmarshalBinary(b []byte) error {
	return conv.UnmarshalBinary(s, b)
}

func (s *State) MarshalBinary() ([]byte, error) {
	return conv.MarshalBinary(s)
}

func (s *State) Marshal(b *cryptobyte.Builder) error {
	b.AddValue(&s.cred)
	b.AddValue(&s.nonce)
	b.AddUint16(uint16(len(s.presCtx)))
	b.AddBytes(s.presCtx)
	return nil
}

func (s *State) Unmarshal(str *cryptobyte.String) bool {
	var n uint16
	s.cred.ID = s.ID
	if !s.cred.Unmarshal(str) ||
		!s.nonce.Unmarshal(str) ||
		!str.ReadUint16(&n) {
		return false
	}

	s.presCtx = make([]byte, n)
	return str.CopyBytes(s.presCtx)
}

func (s *State) Present(rnd io.Reader) (*uint16, *Presentation, error) {
	if s.nonce.available == 0 {
		return nil, nil, ErrLimitExceeded
	}

	if rnd == nil {
		rnd = rand.Reader
	}

	suite := s.cred.ID.getSuite()
	a := suite.randomScalar(rnd)
	r := suite.randomScalar(rnd)
	z := suite.randomScalar(rnd)

	p := &Presentation{ID: s.ID}
	suite.initElt(&p.u, &p.uPrimeCom, &p.m1Com, &p.tag)
	p.u.Mul(s.cred.u, a)
	p.uPrimeCom.Mul(s.cred.uPrime, a)
	rG := suite.newElement()
	rG.MulGen(r)
	p.uPrimeCom.Add(p.uPrimeCom, rG)

	p.m1Com.Mul(p.u, s.cred.m1)
	t := suite.newElement()
	t.Mul(suite.genH, z)
	p.m1Com.Add(p.m1Com, t)

	genT := suite.hashToGroup(s.presCtx, labelTag)
	nonce := s.nonce.AddRandom(rnd)
	nonceScl := suite.newScalar().SetUint64(uint64(nonce))
	e := suite.newScalar()
	e.Add(nonceScl, s.cred.m1)
	e.Inv(e)
	p.tag.Mul(genT, e)

	V := suite.newElement()
	V.Mul(s.cred.x1, z)
	t.Neg(rG)
	V.Add(V, t)

	m1Tag := suite.newElement()
	m1Tag.Mul(p.tag, s.cred.m1)
	p.makeProof(rnd, genT, V, m1Tag, s.cred.x1, s.cred.m1, r, z, nonceScl)

	return &nonce, p, nil
}

func Verify(
	priv *PrivateKey,
	pres *Presentation,
	reqCtx, presCtx []byte,
	nonce, limit uint16,
) bool {
	if nonce > limit {
		panic(ErrInvalidNonce)
	}

	s := priv.ID.getSuite()
	genT := s.hashToGroup(presCtx, labelTag)
	e := s.newScalar().SetUint64(uint64(nonce))

	m1Tag := s.newElement()
	m1Tag.Mul(pres.tag, e)
	m1Tag.Neg(m1Tag)
	m1Tag.Add(genT, m1Tag)
	return pres.verifyProof(priv, reqCtx, genT, m1Tag)
}
