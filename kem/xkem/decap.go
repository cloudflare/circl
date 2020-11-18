package xkem

import "github.com/cloudflare/circl/kem"

func (x xkem) Decapsulate(skr kem.PrivateKey, ct []byte) ([]byte, error) {
	dh := make([]byte, x.SharedKeySize())
	kemCtx, err := x.coreDecap(dh, skr, ct)
	if err != nil {
		return nil, err
	}
	return x.extractExpand(dh, kemCtx), nil
}

func (x xkem) AuthDecapsulate(skr kem.PrivateKey, ct []byte, pks kem.PublicKey) ([]byte, error) {
	pkS, ok := pks.(xkemPubKey)
	if !ok {
		return nil, kem.ErrTypeMismatch
	}

	dhLen := x.SharedKeySize()
	dh := make([]byte, 2*dhLen)
	kemCtx, err := x.coreDecap(dh[:dhLen], skr, ct)
	if err != nil {
		return nil, err
	}
	x.calcDH(dh[dhLen:], skr.(xkemPrivKey), pkS)

	pkSm, err := pkS.MarshalBinary()
	if err != nil {
		return nil, err
	}
	kemCtx = append(kemCtx, pkSm...)
	return x.extractExpand(dh, kemCtx), nil
}

func (x xkem) coreDecap(dh []byte, skr kem.PrivateKey, ct []byte) ([]byte, error) {
	skR, ok := skr.(xkemPrivKey)
	if !ok {
		return nil, kem.ErrTypeMismatch
	}
	pke, err := x.UnmarshalBinaryPublicKey(ct)
	if err != nil {
		return nil, err
	}
	pkE, ok := pke.(xkemPubKey)
	if !ok {
		return nil, kem.ErrTypeMismatch
	}

	x.calcDH(dh, skR, pkE)

	pkR := skR.Public()
	pkRm, err := pkR.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return append(append([]byte{}, ct...), pkRm...), nil
}
