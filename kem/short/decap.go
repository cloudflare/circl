package short

import "github.com/cloudflare/circl/kem"

func (s short) Decapsulate(skr kem.PrivateKey, ct []byte) []byte {
	dh := make([]byte, s.SharedKeySize())
	kemCtx := s.codeDecap(dh, skr, ct)
	return s.extractExpand(dh, kemCtx)
}

func (s short) AuthDecapsulate(skr kem.PrivateKey, ct []byte, pks kem.PublicKey) []byte {
	pkS, ok := pks.(shortPubKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}

	dhLen := s.SharedKeySize()
	dh := make([]byte, 2*dhLen)
	kemCtx := s.codeDecap(dh[:dhLen], skr, ct)
	s.calcDH(dh[dhLen:], skr.(shortPrivKey), pkS)

	pkSm, err := pkS.MarshalBinary()
	if err != nil {
		panic(err)
	}
	kemCtx = append(kemCtx, pkSm...)
	return s.extractExpand(dh, kemCtx)
}

func (s short) codeDecap(dh []byte, skr kem.PrivateKey, ct []byte) (kemCtx []byte) {
	skR, ok := skr.(shortPrivKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}
	pke, err := s.UnmarshalBinaryPublicKey(ct)
	if err != nil {
		panic(err)
	}
	pkE, ok := pke.(shortPubKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}

	s.calcDH(dh, skR, pkE)

	pkR := skR.Public()
	pkRm, err := pkR.MarshalBinary()
	if err != nil {
		panic(err)
	}
	kemCtx = append(append([]byte{}, ct...), pkRm...)
	return kemCtx
}
