package short

import (
	"crypto"

	"github.com/cloudflare/circl/kem"
)

func (s short) Encapsulate(pkr kem.PublicKey) (ct []byte, ss []byte) {
	pke, ske, err := s.GenerateKey()
	if err != nil {
		panic(err)
	}
	return s.encap(pkr, pke, ske)
}

func (s short) EncapsulateDeterministically(pkr kem.PublicKey, seed []byte) (ct, ss []byte) {
	pke, ske := s.DeriveKey(seed)
	return s.encap(pkr, pke, ske)
}

func (s short) AuthEncapsulate(pkr kem.PublicKey, sks kem.PrivateKey) (ct []byte, ss []byte) {
	pke, ske, err := s.GenerateKey()
	if err != nil {
		panic(err)
	}
	return s.authEncap(pkr, sks, pke, ske)
}

func (s short) AuthEncapsulateDeterministically(pkr kem.PublicKey, seed []byte, sks kem.PrivateKey) (ct, ss []byte) {
	pke, ske := s.DeriveKey(seed)
	return s.authEncap(pkr, sks, pke, ske)
}

func (s short) encap(pkr kem.PublicKey, pke crypto.PublicKey, ske crypto.PrivateKey) (ct []byte, ss []byte) {
	dh := make([]byte, s.SharedKeySize())
	enc, kemCtx := s.coreEncap(dh, pkr, ske, pke)
	ss = s.extractExpand(dh, kemCtx)
	return enc, ss
}

func (s short) authEncap(
	pkr kem.PublicKey,
	sks kem.PrivateKey,
	pke crypto.PublicKey,
	ske crypto.PrivateKey,
) (ct []byte, ss []byte) {
	skS, ok := sks.(shortPrivKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}

	dhLen := s.SharedKeySize()
	dh := make([]byte, 2*dhLen)
	enc, kemCtx := s.coreEncap(dh[:dhLen], pkr, ske, pke)
	s.calcDH(dh[dhLen:], skS, pkr.(shortPubKey))

	pkS := skS.Public()
	pkSm, err := pkS.MarshalBinary()
	if err != nil {
		panic(err)
	}
	kemCtx = append(kemCtx, pkSm...)

	ss = s.extractExpand(dh, kemCtx)
	return enc, ss
}

func (s short) coreEncap(
	dh []byte,
	pkr kem.PublicKey,
	ske crypto.PrivateKey,
	pke crypto.PublicKey,
) (enc []byte, kemCtx []byte) {
	pkR, ok := pkr.(shortPubKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}
	pkE, ok := pke.(shortPubKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}
	skE, ok := ske.(shortPrivKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}

	s.calcDH(dh, skE, pkR)

	enc, err := pkE.MarshalBinary()
	if err != nil {
		panic(err)
	}
	pkRm, err := pkR.MarshalBinary()
	if err != nil {
		panic(err)
	}
	kemCtx = append(append([]byte{}, enc...), pkRm...)

	return enc, kemCtx
}
