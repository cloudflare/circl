package oprf

import (
	"encoding/binary"
	"io"

	"github.com/cloudflare/circl/group"
)

type PrivateKey struct {
	p   params
	k   group.Scalar
	pub *PublicKey
}

type PublicKey struct {
	p params
	e group.Element
}

func (k *PrivateKey) MarshalBinary() ([]byte, error) { return k.k.MarshalBinary() }
func (k *PublicKey) MarshalBinary() ([]byte, error)  { return k.e.MarshalBinaryCompress() }

func (k *PrivateKey) UnmarshalBinary(s Suite, data []byte) error {
	p, ok := s.(params)
	if !ok {
		return ErrInvalidSuite
	}
	k.p = p
	k.k = k.p.group.NewScalar()

	return k.k.UnmarshalBinary(data)
}

func (k *PublicKey) UnmarshalBinary(s Suite, data []byte) error {
	p, ok := s.(params)
	if !ok {
		return ErrInvalidSuite
	}
	k.p = p
	k.e = k.p.group.NewElement()

	return k.e.UnmarshalBinary(data)
}

func (k *PrivateKey) Public() *PublicKey {
	if k.pub == nil {
		k.pub = &PublicKey{k.p, k.p.group.NewElement().MulGen(k.k)}
	}

	return k.pub
}

// GenerateKey generates a private key compatible with the suite.
func GenerateKey(s Suite, rnd io.Reader) (*PrivateKey, error) {
	if rnd == nil {
		return nil, io.ErrNoProgress
	}

	p, ok := s.(params)
	if !ok {
		return nil, ErrInvalidSuite
	}
	privateKey := p.group.RandomScalar(rnd)

	return &PrivateKey{p, privateKey, nil}, nil
}

// DeriveKey generates a private key from a given seed and optional info string.
func DeriveKey(s Suite, mode Mode, seed, info []byte) (*PrivateKey, error) {
	const maxTries = 255
	p, ok := s.(params)
	if !ok {
		return nil, ErrInvalidSuite
	}
	if !isValidMode(mode) {
		return nil, ErrInvalidMode
	}
	p.m = mode

	lenInfo := []byte{0, 0}
	binary.BigEndian.PutUint16(lenInfo, uint16(len(info)))
	deriveInput := append(append(append([]byte{}, seed...), lenInfo...), info...)

	dst := p.getDST(deriveKeyPairDST)
	zero := p.group.NewScalar()
	privateKey := p.group.NewScalar()
	for counter := byte(0); privateKey.IsEqual(zero); counter++ {
		if counter > maxTries {
			return nil, ErrDeriveKeyPairError
		}
		privateKey = p.group.HashToScalar(append(deriveInput, counter), dst)
	}

	return &PrivateKey{p, privateKey, nil}, nil
}
