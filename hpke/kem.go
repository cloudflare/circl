package hpke

import (
	"crypto"
	"errors"

	"github.com/cloudflare/circl/kem"
)

func (s *Sender) encap(pk crypto.PublicKey) (ct []byte, ss []byte, err error) {
	pub, ok := pk.(kem.PublicKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}

	k := s.GetKem()
	if s.seed == nil {
		ct, ss, err = k.Encapsulate(pub)
	} else if len(s.seed) >= k.SeedSize() {
		ct, ss, err = k.EncapsulateDeterministically(pub, s.seed)
	} else {
		return nil, nil, kem.ErrSeedSize
	}

	return ct, ss, err
}

func (s *Sender) encapAuth(pk crypto.PublicKey, sk crypto.PrivateKey) (ct []byte, ss []byte, err error) {
	pub, ok := pk.(kem.PublicKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}
	priv, ok := sk.(kem.PrivateKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}

	k, err := s.getAuthKem()
	if err != nil {
		return nil, nil, err
	}

	if s.seed == nil {
		ct, ss, err = k.AuthEncapsulate(pub, priv)
	} else {
		ct, ss, err = k.AuthEncapsulateDeterministically(pub, s.seed, priv)
	}
	return ct, ss, err
}

func (r *Receiver) decap(sk crypto.PrivateKey, ct []byte) ([]byte, error) {
	priv, ok := sk.(kem.PrivateKey)
	if !ok {
		return nil, kem.ErrTypeMismatch
	}

	k := r.GetKem()
	return k.Decapsulate(priv, ct)
}

func (r *Receiver) decapAuth(sk crypto.PrivateKey, ct []byte, pk crypto.PublicKey) ([]byte, error) {
	pub, ok := pk.(kem.PublicKey)
	if !ok {
		return nil, kem.ErrTypeMismatch
	}
	priv, ok := sk.(kem.PrivateKey)
	if !ok {
		return nil, kem.ErrTypeMismatch
	}

	k, err := r.getAuthKem()
	if err != nil {
		return nil, err
	}

	return k.AuthDecapsulate(priv, ct, pub)
}

func (s Suite) GetKem() kem.Scheme { return kemParams[s.KemID] }

func (s Suite) getAuthKem() (kem.AuthScheme, error) {
	k := s.GetKem()
	a, ok := k.(kem.AuthScheme)
	if !ok {
		return nil, errors.New("kem is not authenticated")
	}
	return a, nil
}
