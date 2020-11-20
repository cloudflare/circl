package hpke

import (
	"github.com/cloudflare/circl/kem"
)

func (s *Sender) encap(pk kem.PublicKey) (ct []byte, ss []byte, err error) {
	k := kemParams[s.KemID]()

	if s.seed == nil {
		ct, ss, err = k.Encapsulate(pk)
	} else if len(s.seed) >= k.SeedSize() {
		ct, ss, err = k.EncapsulateDeterministically(pk, s.seed)
	} else {
		return nil, nil, kem.ErrSeedSize
	}

	return ct, ss, err
}

func (s *Sender) encapAuth(
	pk kem.PublicKey,
	sk kem.PrivateKey,
) (ct []byte, ss []byte, err error) {
	k := kemParams[s.KemID]()

	if s.seed == nil {
		ct, ss, err = k.AuthEncapsulate(pk, sk)
	} else {
		ct, ss, err = k.AuthEncapsulateDeterministically(pk, s.seed, sk)
	}

	return ct, ss, err
}

func (r *Receiver) decap(sk kem.PrivateKey, ct []byte) ([]byte, error) {
	k := kemParams[r.KemID]()
	return k.Decapsulate(sk, ct)
}

func (r *Receiver) decapAuth(
	sk kem.PrivateKey,
	ct []byte,
	pk kem.PublicKey,
) ([]byte, error) {
	k := kemParams[r.KemID]()
	return k.AuthDecapsulate(sk, ct, pk)
}
