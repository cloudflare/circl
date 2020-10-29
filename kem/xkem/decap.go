package xkem

import "github.com/cloudflare/circl/kem"

func (x xkem) Decapsulate(skr kem.PrivateKey, ct []byte) []byte {
	dh := make([]byte, x.SharedKeySize())
	kemCtx := x.coreDecap(dh, skr, ct)
	return x.extractExpand(dh, kemCtx)
}

func (x xkem) AuthDecapsulate(skr kem.PrivateKey, ct []byte, pks kem.PublicKey) []byte {
	pkS, ok := pks.(xkemPubKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}

	dhLen := x.SharedKeySize()
	dh := make([]byte, 2*dhLen)
	kemCtx := x.coreDecap(dh[:dhLen], skr, ct)
	x.calcDH(dh[dhLen:], skr.(xkemPrivKey), pkS)

	pkSm, err := pkS.MarshalBinary()
	if err != nil {
		panic(err)
	}
	kemCtx = append(kemCtx, pkSm...)
	return x.extractExpand(dh, kemCtx)
}

func (x xkem) coreDecap(dh []byte, skr kem.PrivateKey, ct []byte) (kemCtx []byte) {
	skR, ok := skr.(xkemPrivKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}
	pke, err := x.UnmarshalBinaryPublicKey(ct)
	if err != nil {
		panic(err)
	}
	pkE, ok := pke.(xkemPubKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}

	x.calcDH(dh, skR, pkE)

	pkR := skR.Public()
	pkRm, err := pkR.MarshalBinary()
	if err != nil {
		panic(err)
	}
	kemCtx = append(append([]byte{}, ct...), pkRm...)
	return kemCtx
}
