package slhdsa

// See FIPS 205 -- Section 5
// Winternitz One-Time Signature Plus Scheme

const (
	wotsW    = 16 // wotsW is w = 2^lg_w, where lg_w = 4.
	wotsLen2 = 3  // wotsLen2 is len_2 fixed to 3.
)

type (
	wotsPublicKey []byte // n bytes
	wotsSignature []byte // wotsLen()*n bytes
)

func (p *params) wotsSigSize() uint32 { return p.wotsLen() * p.n }
func (p *params) wotsLen() uint32     { return p.wotsLen1() + wotsLen2 }
func (p *params) wotsLen1() uint32    { return 2 * p.n }

func (ws *wotsSignature) fromBytes(p *params, c *cursor) {
	*ws = c.Next(p.wotsSigSize())
}

// See FIPS 205 -- Section 5 -- Algorithm 5.
func (s *state) chain(x []byte, index, step uint32, addr address) (out []byte) {
	out = x
	s.F.address.Set(addr)
	for j := index; j < index+step; j++ {
		s.F.address.SetHashAddress(j)
		s.F.SetMessage(out)
		out = s.F.Final()
	}
	return
}

// See FIPS 205 -- Section 5.1 -- Algorithm 6.
func (s *statePriv) wotsPkGen(addr address) wotsPublicKey {
	s.PRF.address.Set(addr)
	s.PRF.address.SetTypeAndClear(addressWotsPrf)
	s.PRF.address.SetKeyPairAddress(addr.GetKeyPairAddress())

	s.T.address.Set(addr)
	s.T.address.SetTypeAndClear(addressWotsPk)
	s.T.address.SetKeyPairAddress(addr.GetKeyPairAddress())

	s.T.Reset()
	wotsLen := s.wotsLen()
	for i := uint32(0); i < wotsLen; i++ {
		s.PRF.address.SetChainAddress(i)
		sk := s.PRF.Final()

		addr.SetChainAddress(i)
		tmpi := s.chain(sk, 0, wotsW-1, addr)

		s.T.WriteMessage(tmpi)
	}

	return s.T.Final()
}

// See FIPS 205 -- Section 5.2 -- Algorithm 7.
func (s *statePriv) wotsSign(sig wotsSignature, msg []byte, addr address) {
	curSig := cursor(sig)
	wotsLen1 := s.wotsLen1()
	csum := wotsLen1 * (wotsW - 1)

	s.PRF.address.Set(addr)
	s.PRF.address.SetTypeAndClear(addressWotsPrf)
	s.PRF.address.SetKeyPairAddress(addr.GetKeyPairAddress())

	for i := uint32(0); i < wotsLen1; i++ {
		s.PRF.address.SetChainAddress(i)
		sk := s.PRF.Final()

		addr.SetChainAddress(i)
		msgi := uint32((msg[i/2] >> ((1 - (i & 1)) << 2)) & 0xF)
		sigi := s.chain(sk, 0, msgi, addr)
		copy(curSig.Next(s.n), sigi)
		csum -= msgi
	}

	for i := uint32(0); i < wotsLen2; i++ {
		s.PRF.address.SetChainAddress(wotsLen1 + i)
		sk := s.PRF.Final()

		addr.SetChainAddress(wotsLen1 + i)
		csumi := (csum >> (8 - 4*i)) & 0xF
		sigi := s.chain(sk, 0, csumi, addr)
		copy(curSig.Next(s.n), sigi)
	}
}

// See FIPS 205 -- Section 5.3 -- Algorithm 8.
func (s *state) wotsPkFromSig(
	sig wotsSignature, msg []byte, addr address,
) wotsPublicKey {
	wotsLen1 := s.wotsLen1()
	csum := wotsLen1 * (wotsW - 1)

	s.T.address.Set(addr)
	s.T.address.SetTypeAndClear(addressWotsPk)
	s.T.address.SetKeyPairAddress(addr.GetKeyPairAddress())

	s.T.Reset()
	curSig := cursor(sig)

	for i := uint32(0); i < wotsLen1; i++ {
		addr.SetChainAddress(i)
		msgi := uint32((msg[i/2] >> ((1 - (i & 1)) << 2)) & 0xF)
		sigi := s.chain(curSig.Next(s.n), msgi, wotsW-1-msgi, addr)

		s.T.WriteMessage(sigi)
		csum -= msgi
	}

	for i := uint32(0); i < wotsLen2; i++ {
		addr.SetChainAddress(wotsLen1 + i)
		csumi := (csum >> (8 - 4*i)) & 0xF
		sigi := s.chain(curSig.Next(s.n), csumi, wotsW-1-csumi, addr)

		s.T.WriteMessage(sigi)
	}

	return s.T.Final()
}
