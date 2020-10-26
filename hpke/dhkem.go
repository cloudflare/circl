package hpke

import (
	"crypto"
	"errors"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/short"
)

func (m Mode) GetKem() (kem.Scheme, error) {
	var dhkem kem.Scheme

	switch m.KemInfo {
	case DHKemP256hkdfsha256:
		dhkem = short.New(short.P256hkdfsha256, []byte(versionLabel))
	case DHKemP384hkdfsha384:
		dhkem = short.New(short.P256hkdfsha256, []byte(versionLabel))
	case DHKemP521hkdfsha512:
		dhkem = short.New(short.P256hkdfsha256, []byte(versionLabel))
	case DHKemX25519hkdfsha256, DHKemX448hkdfsha512:
		panic("not implemented yet")
	default:
		return nil, errors.New("wrong DHkemID")
	}
	return dhkem, nil
}

func (m Mode) encap(pkr crypto.PublicKey) (enc, shared []byte, err error) {
	dhkem, err := m.GetKem()
	if err != nil {
		return nil, nil, err
	}
	enc, shared = dhkem.Encapsulate(pkr.(kem.PublicKey))
	return enc, shared, nil
}

func (m Mode) decap(skr crypto.PrivateKey, enc []byte) (ss []byte, err error) {
	dhkem, err := m.GetKem()
	if err != nil {
		return nil, err
	}
	return dhkem.Decapsulate(skr.(kem.PrivateKey), enc), nil
}
