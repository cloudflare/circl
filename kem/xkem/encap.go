package xkem

import (
	"crypto"

	"github.com/cloudflare/circl/kem"
)

func (x xkem) Encapsulate(pkr kem.PublicKey) (ct []byte, ss []byte, err error) {
	pke, ske, err := x.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return x.encap(pkr, pke, ske)
}

func (x xkem) EncapsulateDeterministically(pkr kem.PublicKey, seed []byte) (ct, ss []byte, err error) {
	pke, ske := x.DeriveKey(seed)
	return x.encap(pkr, pke, ske)
}

func (x xkem) AuthEncapsulate(pkr kem.PublicKey, sks kem.PrivateKey) (ct []byte, ss []byte, err error) {
	pke, ske, err := x.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return x.authEncap(pkr, sks, pke, ske)
}

func (x xkem) AuthEncapsulateDeterministically(pkr kem.PublicKey, seed []byte, sks kem.PrivateKey) (ct, ss []byte, err error) {
	pke, ske := x.DeriveKey(seed)
	return x.authEncap(pkr, sks, pke, ske)
}

func (x xkem) encap(pkr kem.PublicKey, pke crypto.PublicKey, ske crypto.PrivateKey) (ct []byte, ss []byte, err error) {
	dh := make([]byte, x.size)
	enc, kemCtx, err := x.coreEncap(dh, pkr, ske, pke)
	if err != nil {
		return nil, nil, err
	}
	ss = x.extractExpand(dh, kemCtx)
	return enc, ss, nil
}

func (x xkem) authEncap(
	pkr kem.PublicKey,
	sks kem.PrivateKey,
	pke crypto.PublicKey,
	ske crypto.PrivateKey,
) (ct []byte, ss []byte, err error) {
	skS, ok := sks.(xkemPrivKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}

	dhLen := x.size
	dh := make([]byte, 2*dhLen)
	enc, kemCtx, err := x.coreEncap(dh[:dhLen], pkr, ske, pke)
	if err != nil {
		return nil, nil, err
	}
	x.calcDH(dh[dhLen:], skS, pkr.(xkemPubKey))

	pkS := skS.Public()
	pkSm, err := pkS.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	kemCtx = append(kemCtx, pkSm...)

	ss = x.extractExpand(dh, kemCtx)
	return enc, ss, nil
}

func (x xkem) coreEncap(
	dh []byte,
	pkr kem.PublicKey,
	ske crypto.PrivateKey,
	pke crypto.PublicKey,
) (enc []byte, kemCtx []byte, err error) {
	pkR, ok := pkr.(xkemPubKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}
	skE, ok := ske.(xkemPrivKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}
	pkE, ok := pke.(xkemPubKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}

	x.calcDH(dh, skE, pkR)

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
