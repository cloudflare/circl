package shortkem

import "github.com/cloudflare/circl/kem"

func (s short) Encapsulate(pkr kem.PublicKey) (ct []byte, ss []byte, err error) {
	pke, ske, err := s.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return s.encap(pkr, pke, ske)
}

func (s short) EncapsulateDeterministically(pkr kem.PublicKey, seed []byte) (ct, ss []byte, err error) {
	pke, ske := s.DeriveKey(seed)
	return s.encap(pkr, pke, ske)
}

func (s short) AuthEncapsulate(pkr kem.PublicKey, sks kem.PrivateKey) (ct []byte, ss []byte, err error) {
	pke, ske, err := s.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return s.authEncap(pkr, sks, pke, ske)
}

func (s short) AuthEncapsulateDeterministically(pkr kem.PublicKey, seed []byte, sks kem.PrivateKey) (ct, ss []byte, err error) {
	pke, ske := s.DeriveKey(seed)
	return s.authEncap(pkr, sks, pke, ske)
}

func (s short) encap(pkr kem.PublicKey, pke kem.PublicKey, ske kem.PrivateKey) (ct []byte, ss []byte, err error) {
	dh := make([]byte, s.byteSize())
	enc, kemCtx, err := s.coreEncap(dh, pkr, ske, pke)
	if err != nil {
		return nil, nil, err
	}
	ss = s.extractExpand(dh, kemCtx)
	return enc, ss, nil
}

func (s short) authEncap(pkr kem.PublicKey, sks kem.PrivateKey, pke kem.PublicKey, ske kem.PrivateKey) (ct []byte, ss []byte, err error) {
	skS, ok := sks.(shortPrivKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}

	dhLen := s.byteSize()
	dh := make([]byte, 2*dhLen)
	enc, kemCtx, err := s.coreEncap(dh[:dhLen], pkr, ske, pke)
	if err != nil {
		return nil, nil, err
	}
	s.calcDH(dh[dhLen:], skS, pkr.(shortPubKey))

	pkS := skS.Public()
	pkSm, err := pkS.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	kemCtx = append(kemCtx, pkSm...)

	ss = s.extractExpand(dh, kemCtx)
	return enc, ss, nil
}

func (s short) coreEncap(
	dh []byte,
	pkr kem.PublicKey,
	ske kem.PrivateKey,
	pke kem.PublicKey,
) (enc []byte, kemCtx []byte, err error) {
	pkR, ok := pkr.(shortPubKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}
	skE, ok := ske.(shortPrivKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}
	pkE, ok := pke.(shortPubKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}

	s.calcDH(dh, skE, pkR)

	enc, err = pkE.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	pkRm, err := pkR.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	kemCtx = append(append([]byte{}, enc...), pkRm...)

	return enc, kemCtx, nil
}
