package hpke

import (
	"errors"

	"github.com/cloudflare/circl/kem"
)

func (s *Sender) encap(pk kem.PublicKey) (ct []byte, ss []byte, err error) {
	k := s.getKem()
	if s.seed == nil {
		ct, ss, err = k.Encapsulate(pk)
	} else if len(s.seed) >= k.SeedSize() {
		ct, ss, err = k.EncapsulateDeterministically(pk, s.seed)
	} else {
		return nil, nil, kem.ErrSeedSize
	}

	return ct, ss, err
}

func (s *Sender) encapAuth(pk kem.PublicKey, sk kem.PrivateKey) (ct []byte, ss []byte, err error) {
	k, err := s.getAuthKem()
	if err != nil {
		return nil, nil, err
	}

	if s.seed == nil {
		ct, ss, err = k.AuthEncapsulate(pk, sk)
	} else {
		ct, ss, err = k.AuthEncapsulateDeterministically(pk, s.seed, sk)
	}
	return ct, ss, err
}

func (r *Receiver) decap(sk kem.PrivateKey, ct []byte) ([]byte, error) {
	return r.getKem().Decapsulate(sk, ct)
}

func (r *Receiver) decapAuth(sk kem.PrivateKey, ct []byte, pk kem.PublicKey) ([]byte, error) {
	k, err := r.getAuthKem()
	if err != nil {
		return nil, err
	}

	return k.AuthDecapsulate(sk, ct, pk)
}

func (s Suite) getKem() kem.Scheme { return kemParams[s.KemID]() }

func (s Suite) getAuthKem() (kem.AuthScheme, error) {
	k := s.getKem()
	a, ok := k.(kem.AuthScheme)
	if !ok {
		return nil, errors.New("kem is not authenticated")
	}
	return a, nil
}
