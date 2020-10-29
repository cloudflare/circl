package hpke

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/short"
)

func (s *Sender) encap(pk crypto.PublicKey) (ct []byte, ss []byte, err error) {
	pub, ok := pk.(kem.PublicKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}

	k, err := s.GetKem()
	if err != nil {
		return nil, nil, err
	}

	if s.seed == nil {
		fmt.Println("\nrandom")
		ct, ss = k.Encapsulate(pub)
	} else if len(s.seed) >= k.SeedSize() {
		fmt.Println("\ndeter")
		ct, ss = k.EncapsulateDeterministically(pub, s.seed)
	} else {
		return nil, nil, kem.ErrSeedSize
	}
	return ct, ss, nil
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
		ct, ss = k.AuthEncapsulate(pub, priv)
	} else {
		ct, ss = k.AuthEncapsulateDeterministically(pub, s.seed, priv)
	}
	return ct, ss, nil
}

func (r *Receiver) decap(sk crypto.PrivateKey, ct []byte) ([]byte, error) {
	priv, ok := sk.(kem.PrivateKey)
	if !ok {
		return nil, kem.ErrTypeMismatch
	}

	k, err := r.GetKem()
	if err != nil {
		return nil, err
	}

	ss := k.Decapsulate(priv, ct)
	return ss, nil
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

	ss := k.AuthDecapsulate(priv, ct, pub)
	return ss, nil
}

func (s Suite) getAuthKem() (kem.AuthScheme, error) {
	k, err := s.GetKem()
	if err != nil {
		return nil, err
	}
	a, ok := k.(kem.AuthScheme)
	if !ok {
		return nil, errors.New("kem is not authenticated")
	}
	return a, nil
}

func (s Suite) GetKem() (dhkem kem.Scheme, err error) {
	switch s.KemID {
	case KemP256Sha256, KemP384Sha384, KemP521Sha512:
		dhkem = short.New(s.KemID, []byte(versionLabel))
	case KemX25519Sha256, KemX448Sha512:
		panic("not implemented yet")
	default:
		err = errors.New("wrong kemID")
	}
	return
}
