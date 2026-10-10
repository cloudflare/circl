package arc

import "io"

type (
	reqProof  proof
	resProof  proof
	presProof proof
)

func (p *reqProof) init(s *suite)  { (*proof)(p).init(s, 4) }
func (p *resProof) init(s *suite)  { (*proof)(p).init(s, 7) }
func (p *presProof) init(s *suite) { (*proof)(p).init(s, 4) }

func (c *CredentialRequest) build(b *builder, sc *[4]scalarIndex) {
	m1Var, m2Var, r1Var, r2Var := sc[0], sc[1], sc[2], sc[3]

	genGVar := b.AppendElement([]byte("genG"), b.suite.genG)
	genHVar := b.AppendElement([]byte("genH"), b.suite.genH)
	m1EncVar := b.AppendElement([]byte("m1Enc"), c.m1)
	m2EncVar := b.AppendElement([]byte("m2Enc"), c.m2)

	b.Constrain(m1EncVar, mul{m1Var, genGVar}, mul{r1Var, genHVar})
	b.Constrain(m2EncVar, mul{m2Var, genGVar}, mul{r2Var, genHVar})
}

func (c *CredentialRequest) makeProof(rnd io.Reader, fin *Finalizer) {
	p := newProver(c.ID, labelCRequest)

	var sc [4]scalarIndex
	sc[0] = p.AppendScalar([]byte("m1"), fin.m1)
	sc[1] = p.AppendScalar([]byte("m2"), fin.m2)
	sc[2] = p.AppendScalar([]byte("r1"), fin.r1)
	sc[3] = p.AppendScalar([]byte("r2"), fin.r2)

	c.build(&p.builder, &sc)
	c.proof = reqProof(p.Prove(rnd))
}

func (c *CredentialRequest) verifyProof() bool {
	v := newVerifier(c.ID, labelCRequest)

	var sc [4]scalarIndex
	sc[0] = v.AppendScalar([]byte("m1"))
	sc[1] = v.AppendScalar([]byte("m2"))
	sc[2] = v.AppendScalar([]byte("r1"))
	sc[3] = v.AppendScalar([]byte("r2"))

	c.build(&v.builder, &sc)
	return v.Verify((*proof)(&c.proof))
}

func (c *CredentialResponse) build(
	b *builder, sc *[7]scalarIndex, req *CredentialRequest, pub *PublicKey,
) {
	x0Var, x1Var, x2Var, x0BliVar := sc[0], sc[1], sc[2], sc[3]
	bVar, t1Var, t2Var := sc[4], sc[5], sc[6]

	genGVar := b.AppendElement([]byte("genG"), b.suite.genG)
	genHVar := b.AppendElement([]byte("genH"), b.suite.genH)
	m1EncVar := b.AppendElement([]byte("m1Enc"), req.m1)
	m2EncVar := b.AppendElement([]byte("m2Enc"), req.m2)
	uVar := b.AppendElement([]byte("U"), c.u)
	encUPrimeVar := b.AppendElement([]byte("encUPrime"), c.encUPrime)
	X0Var := b.AppendElement([]byte("X0"), pub.x0)
	X1Var := b.AppendElement([]byte("X1"), pub.x1)
	X2Var := b.AppendElement([]byte("X2"), pub.x2)
	x0AuxVar := b.AppendElement([]byte("X0Aux"), c.x0Aux)
	x1AuxVar := b.AppendElement([]byte("X1Aux"), c.x1Aux)
	x2AuxVar := b.AppendElement([]byte("X2Aux"), c.x2Aux)
	hAuxVar := b.AppendElement([]byte("HAux"), c.hAux)

	b.Constrain(X0Var, mul{x0Var, genGVar}, mul{x0BliVar, genHVar})
	b.Constrain(X1Var, mul{x1Var, genHVar})
	b.Constrain(X2Var, mul{x2Var, genHVar})
	b.Constrain(hAuxVar, mul{bVar, genHVar})
	b.Constrain(x0AuxVar, mul{x0BliVar, hAuxVar})
	b.Constrain(x1AuxVar, mul{t1Var, genHVar})
	b.Constrain(x1AuxVar, mul{bVar, X1Var})
	b.Constrain(x2AuxVar, mul{bVar, X2Var})
	b.Constrain(x2AuxVar, mul{t2Var, genHVar})
	b.Constrain(uVar, mul{bVar, genGVar})
	b.Constrain(encUPrimeVar, mul{bVar, X0Var}, mul{t1Var, m1EncVar},
		mul{t2Var, m2EncVar})
}

func (c *CredentialResponse) makeProof(
	rnd io.Reader,
	priv *PrivateKey,
	b scalar,
	req *CredentialRequest,
) {
	pub := priv.PublicKey()
	p := newProver(pub.ID, labelCResponse)

	var sc [7]scalarIndex
	t1 := b.Group().NewScalar()
	t2 := b.Group().NewScalar()
	sc[0] = p.AppendScalar([]byte("x0"), priv.x0)
	sc[1] = p.AppendScalar([]byte("x1"), priv.x1)
	sc[2] = p.AppendScalar([]byte("x2"), priv.x2)
	sc[3] = p.AppendScalar([]byte("x0Blinding"), priv.x0Blinding)
	sc[4] = p.AppendScalar([]byte("b"), b)
	sc[5] = p.AppendScalar([]byte("t1"), t1.Mul(b, priv.x1))
	sc[6] = p.AppendScalar([]byte("t2"), t2.Mul(b, priv.x2))

	c.build(&p.builder, &sc, req, &pub)
	c.proof = resProof(p.Prove(rnd))
}

func (c *CredentialResponse) verifyProof(pub *PublicKey, req *CredentialRequest) bool {
	v := newVerifier(pub.ID, labelCResponse)

	var sc [7]scalarIndex
	sc[0] = v.AppendScalar([]byte("x0"))
	sc[1] = v.AppendScalar([]byte("x1"))
	sc[2] = v.AppendScalar([]byte("x2"))
	sc[3] = v.AppendScalar([]byte("x0Blinding"))
	sc[4] = v.AppendScalar([]byte("b"))
	sc[5] = v.AppendScalar([]byte("t1"))
	sc[6] = v.AppendScalar([]byte("t2"))

	c.build(&v.builder, &sc, req, pub)
	return v.Verify((*proof)(&c.proof))
}

func (p *Presentation) build(
	b *builder, sc *[4]scalarIndex, x1, generatorT, V, m1Tag elt,
) {
	m1Var, zVar, rNegVar, nonceVar := sc[0], sc[1], sc[2], sc[3]

	genGVar := b.AppendElement([]byte("genG"), b.suite.genG)
	genHVar := b.AppendElement([]byte("genH"), b.suite.genH)
	UVar := b.AppendElement([]byte("U"), p.u)
	_ = b.AppendElement([]byte("UPrimeCommit"), p.uPrimeCom)
	m1CommitVar := b.AppendElement([]byte("m1Commit"), p.m1Com)
	VVar := b.AppendElement([]byte("V"), V)
	X1Var := b.AppendElement([]byte("X1"), x1)
	tagVar := b.AppendElement([]byte("tag"), p.tag)
	genTVar := b.AppendElement([]byte("genT"), generatorT)
	m1TagVar := b.AppendElement([]byte("m1Tag"), m1Tag)

	b.Constrain(m1CommitVar, mul{m1Var, UVar}, mul{zVar, genHVar})
	b.Constrain(VVar, mul{zVar, X1Var}, mul{rNegVar, genGVar})
	b.Constrain(genTVar, mul{m1Var, tagVar}, mul{nonceVar, tagVar})
	b.Constrain(m1TagVar, mul{m1Var, tagVar})
}

func (p *Presentation) makeProof(
	rnd io.Reader,
	generatorT, V, m1Tag, x1 elt,
	m1, r, z, nonce scalar,
) {
	pp := newProver(p.ID, labelCPresentation)

	var sc [4]scalarIndex
	sc[0] = pp.AppendScalar([]byte("m1"), m1)
	sc[1] = pp.AppendScalar([]byte("z"), z)
	sc[2] = pp.AppendScalar([]byte("-r"), r.Neg(r))
	sc[3] = pp.AppendScalar([]byte("nonce"), nonce)

	p.build(&pp.builder, &sc, x1, generatorT, V, m1Tag)
	p.proof = presProof(pp.Prove(rnd))
}

func (p *Presentation) verifyProof(
	priv *PrivateKey,
	reqCtx []byte,
	generatorT, m1Tag elt,
) bool {
	s := priv.ID.getSuite()
	m2 := s.hashToScalar(reqCtx, labelRequestContext)
	m2.Mul(m2, priv.x2)
	t := s.newElement()
	V := s.newElement()
	V.Mul(p.u, priv.x0)
	V.Add(V, t.Mul(p.m1Com, priv.x1))
	V.Add(V, t.Mul(p.u, m2))
	V.Add(V, t.Neg(p.uPrimeCom))

	v := newVerifier(priv.ID, labelCPresentation)

	var sc [4]scalarIndex
	sc[0] = v.AppendScalar([]byte("m1"))
	sc[1] = v.AppendScalar([]byte("z"))
	sc[2] = v.AppendScalar([]byte("-r"))
	sc[3] = v.AppendScalar([]byte("nonce"))

	pub := priv.PublicKey()
	p.build(&v.builder, &sc, pub.x1, generatorT, V, m1Tag)
	return v.Verify((*proof)(&p.proof))
}
