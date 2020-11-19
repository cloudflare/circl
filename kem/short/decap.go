package short

import "github.com/cloudflare/circl/kem"

func (s short) Decapsulate(skr kem.PrivateKey, ct []byte) ([]byte, error) {
	dh := make([]byte, s.byteSize())
	kemCtx, err := s.coreDecap(dh, skr, ct)
	if err != nil {
		return nil, err
	}
	return s.extractExpand(dh, kemCtx), nil
}

func (s short) AuthDecapsulate(skr kem.PrivateKey, ct []byte, pks kem.PublicKey) ([]byte, error) {
	pkS, ok := pks.(shortPubKey)
	if !ok {
		return nil, kem.ErrTypeMismatch
	}

	dhLen := s.byteSize()
	dh := make([]byte, 2*dhLen)
	kemCtx, err := s.coreDecap(dh[:dhLen], skr, ct)
	if err != nil {
		return nil, err
	}
	s.calcDH(dh[dhLen:], skr.(shortPrivKey), pkS)

	pkSm, err := pkS.MarshalBinary()
	if err != nil {
		return nil, err
	}
	kemCtx = append(kemCtx, pkSm...)
	return s.extractExpand(dh, kemCtx), nil
}

func (s short) coreDecap(dh []byte, skr kem.PrivateKey, ct []byte) ([]byte, error) {
	skR, ok := skr.(shortPrivKey)
	if !ok {
		return nil, kem.ErrTypeMismatch
	}
	pke, err := s.UnmarshalBinaryPublicKey(ct)
	if err != nil {
		return nil, err
	}
	pkE, ok := pke.(shortPubKey)
	if !ok {
		return nil, kem.ErrTypeMismatch
	}

	s.calcDH(dh, skR, pkE)

	pkR := skR.Public()
	pkRm, err := pkR.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return append(append([]byte{}, ct...), pkRm...), nil
}
