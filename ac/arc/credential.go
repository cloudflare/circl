package arc

import (
	"io"
	"slices"

	"github.com/cloudflare/circl/internal/conv"
	"golang.org/x/crypto/cryptobyte"
)

type Finalizer struct {
	m1, m2, r1, r2 scalar
	ID             SuiteID
}

func (f Finalizer) String() string {
	return printAny(f.m1, f.m2, f.r1, f.r2)
}

func (f *Finalizer) UnmarshalBinary(b []byte) error {
	return conv.UnmarshalBinary(f, b)
}

func (f *Finalizer) MarshalBinary() ([]byte, error) {
	return conv.MarshalBinary(f)
}

func (f *Finalizer) Marshal(b *cryptobyte.Builder) error {
	return conv.MarshalSlice(b, f.m1, f.m2, f.r1, f.r2)
}

func (f *Finalizer) Unmarshal(s *cryptobyte.String) bool {
	suite := f.ID.getSuite()
	suite.initScalar(&f.m1, &f.m2, &f.r1, &f.r2)
	return conv.UnmarshalSlice(s, f.m1, f.m2, f.r1, f.r2)
}

func (f *Finalizer) IsEqual(g *Finalizer) bool {
	return f.ID == g.ID && slices.EqualFunc(
		[]scalar{f.m1, f.m2, f.r1, f.r2},
		[]scalar{g.m1, g.m2, g.r1, g.r2},
		scalar.IsEqual)
}

type CredentialRequest struct {
	m1, m2 elt
	proof  reqProof
	ID     SuiteID
}

func (s SuiteID) NewCredentialRequest() (c CredentialRequest) { return }

func (c CredentialRequest) String() string {
	return printAny(c.m1, c.m2, proof(c.proof))
}

func (c *CredentialRequest) UnmarshalBinary(b []byte) error {
	return conv.UnmarshalBinary(c, b)
}

func (c *CredentialRequest) MarshalBinary() ([]byte, error) {
	return conv.MarshalBinary(c)
}

func (c *CredentialRequest) Marshal(b *cryptobyte.Builder) error {
	return conv.MarshalSlice(b, eltCom{c.m1}, eltCom{c.m2}, proof(c.proof))
}

func (c *CredentialRequest) Unmarshal(s *cryptobyte.String) bool {
	suite := c.ID.getSuite()
	suite.initElt(&c.m1, &c.m2)
	c.proof.init(suite)
	return conv.UnmarshalSlice(s, eltCom{c.m1}, eltCom{c.m2}, proof(c.proof))
}

func (c *CredentialRequest) IsEqual(d *CredentialRequest) bool {
	return c.ID == d.ID && slices.EqualFunc(
		[]elt{c.m1, c.m2},
		[]elt{d.m1, d.m2},
		elt.IsEqual,
	) && proof(c.proof).IsEqual(proof(d.proof))
}

type CredentialResponse struct {
	u, encUPrime, x0Aux, x1Aux, x2Aux, hAux elt
	proof                                   resProof
	ID                                      SuiteID
}

func (c CredentialResponse) String() string {
	return printAny(c.u, c.encUPrime, c.x0Aux, c.x1Aux, c.x2Aux, c.hAux, proof(c.proof))
}

func (c *CredentialResponse) UnmarshalBinary(b []byte) error {
	return conv.UnmarshalBinary(c, b)
}

func (c *CredentialResponse) MarshalBinary() ([]byte, error) {
	return conv.MarshalBinary(c)
}

func (c *CredentialResponse) Marshal(b *cryptobyte.Builder) error {
	return conv.MarshalSlice(b,
		eltCom{c.u}, eltCom{c.encUPrime}, eltCom{c.x0Aux}, eltCom{c.x1Aux},
		eltCom{c.x2Aux}, eltCom{c.hAux}, proof(c.proof))
}

func (c *CredentialResponse) Unmarshal(s *cryptobyte.String) bool {
	suite := c.ID.getSuite()
	suite.initElt(&c.u, &c.encUPrime, &c.x0Aux, &c.x1Aux, &c.x2Aux, &c.hAux)
	c.proof.init(suite)
	return conv.UnmarshalSlice(s,
		eltCom{c.u}, eltCom{c.encUPrime}, eltCom{c.x0Aux}, eltCom{c.x1Aux},
		eltCom{c.x2Aux}, eltCom{c.hAux}, proof(c.proof))
}

func (c *CredentialResponse) IsEqual(d *CredentialResponse) bool {
	return c.ID == d.ID && slices.EqualFunc(
		[]elt{c.u, c.encUPrime, c.x0Aux, c.x1Aux, c.x2Aux, c.hAux},
		[]elt{d.u, d.encUPrime, d.x0Aux, d.x1Aux, d.x2Aux, d.hAux},
		elt.IsEqual,
	) && proof(c.proof).IsEqual(proof(d.proof))
}

type Credential struct {
	m1            scalar
	u, uPrime, x1 elt
	ID            SuiteID
}

func (c Credential) String() string {
	return printAny(c.m1, c.u, c.uPrime, c.x1)
}

func (c *Credential) UnmarshalBinary(b []byte) error {
	return conv.UnmarshalBinary(c, b)
}

func (c *Credential) MarshalBinary() ([]byte, error) {
	return conv.MarshalBinary(c)
}

func (c *Credential) Marshal(b *cryptobyte.Builder) error {
	return conv.MarshalSlice(b,
		c.m1, eltCom{c.u}, eltCom{c.uPrime}, eltCom{c.x1})
}

func (c *Credential) Unmarshal(s *cryptobyte.String) bool {
	suite := c.ID.getSuite()
	suite.initScalar(&c.m1)
	suite.initElt(&c.u, &c.uPrime, &c.x1)
	return conv.UnmarshalSlice(s, c.m1, eltCom{c.u}, eltCom{c.uPrime}, eltCom{c.x1})
}

func (c *Credential) IsEqual(d *Credential) bool {
	return c.ID == d.ID && c.m1.IsEqual(d.m1) && slices.EqualFunc(
		[]elt{c.u, c.uPrime, c.x1},
		[]elt{d.u, d.uPrime, d.x1},
		elt.IsEqual)
}

func Request(
	rnd io.Reader, id SuiteID, ctx []byte,
) (fin Finalizer, credReq CredentialRequest) {
	s := id.getSuite()
	fin = Finalizer{
		ID: id,
		m1: s.randomScalar(rnd),
		m2: s.hashToScalar(ctx, labelRequestContext),
		r1: s.randomScalar(rnd),
		r2: s.randomScalar(rnd),
	}

	credReq.ID = id
	s.initElt(&credReq.m1, &credReq.m2)
	t := s.newElement()
	credReq.m1.Add(credReq.m1.MulGen(fin.m1), t.Mul(s.genH, fin.r1))
	credReq.m2.Add(credReq.m2.MulGen(fin.m2), t.Mul(s.genH, fin.r2))
	credReq.makeProof(rnd, &fin)
	return fin, credReq
}

func Response(
	rnd io.Reader, priv *PrivateKey, credReq *CredentialRequest,
) (*CredentialResponse, error) {
	if !credReq.verifyProof() {
		return nil, ErrVerifyReqProof
	}

	pub := priv.PublicKey()
	res := new(CredentialResponse)
	res.ID = priv.ID
	s := priv.ID.getSuite()
	s.initElt(&res.u, &res.encUPrime, &res.x0Aux, &res.x1Aux, &res.x2Aux, &res.hAux)
	res.proof.init(s)

	b := s.randomScalar(rnd)
	res.u.MulGen(b)
	t := s.newElement()
	res.encUPrime.Add(pub.x0, t.Mul(credReq.m1, priv.x1))
	res.encUPrime.Add(res.encUPrime, t.Mul(credReq.m2, priv.x2))
	res.encUPrime.Mul(res.encUPrime, b)

	e := s.newScalar()
	e.Mul(b, priv.x0Blinding)
	res.x0Aux.Mul(s.genH, e)
	res.x1Aux.Mul(pub.x1, b)
	res.x2Aux.Mul(pub.x2, b)
	res.hAux.Mul(s.genH, b)
	res.makeProof(rnd, priv, b, credReq)
	return res, nil
}

func Finalize(
	fin *Finalizer,
	credReq *CredentialRequest,
	credRes *CredentialResponse,
	pub *PublicKey,
) (*Credential, error) {
	if !credRes.verifyProof(pub, credReq) {
		return nil, ErrVerifyResProof
	}

	s := pub.ID.getSuite()
	t := s.newElement()
	uPrime := s.newElement()
	uPrime.Add(credRes.x0Aux, t.Mul(credRes.x1Aux, fin.r1))
	uPrime.Add(uPrime, t.Mul(credRes.x2Aux, fin.r2))
	uPrime.Neg(uPrime)
	uPrime.Add(uPrime, credRes.encUPrime)

	return &Credential{
		ID:     pub.ID,
		m1:     fin.m1.Copy(),
		u:      credRes.u.Copy(),
		uPrime: uPrime,
		x1:     pub.x1.Copy(),
	}, nil
}
