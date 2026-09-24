package ecmr

import (
	"io"

	"github.com/cloudflare/circl/group"
)

type PrivateKey struct {
	scalar group.Scalar
	pub    *PublicKey
}

type PublicKey struct {
	element group.Element
}

func GenerateKey(rnd io.Reader) (*PrivateKey, error) {
	if rnd == nil {
		return nil, ErrNilReader
	}

	scalar := group.P521.RandomNonZeroScalar(rnd)
	return &PrivateKey{scalar: scalar}, nil
}

func (k *PrivateKey) Public() *PublicKey {
	if k.pub == nil {
		element := group.P521.NewElement().MulGen(k.scalar)
		k.pub = &PublicKey{element: element}
	}
	return k.pub
}

func (k *PrivateKey) MarshalBinary() ([]byte, error) {
	if k.scalar == nil {
		return nil, ErrNilKey
	}
	return k.scalar.MarshalBinary()
}

func (k *PrivateKey) UnmarshalBinary(data []byte) error {
	if len(data) != PrivateKeySize {
		return ErrMalformedScalar
	}

	scalar := group.P521.NewScalar()
	if err := scalar.UnmarshalBinary(data); err != nil {
		return ErrMalformedScalar
	}

	if scalar.IsZero() {
		return ErrZeroScalar
	}

	k.scalar = scalar
	k.pub = nil
	return nil
}

func (k *PublicKey) MarshalBinary() ([]byte, error) {
	if k.element == nil {
		return nil, ErrNilKey
	}
	return k.element.MarshalBinary()
}

func (k *PublicKey) UnmarshalBinary(data []byte) error {
	if len(data) != PublicKeySize {
		return ErrMalformedPoint
	}

	element := group.P521.NewElement()
	if err := element.UnmarshalBinary(data); err != nil {
		return ErrMalformedPoint
	}

	if element.IsIdentity() {
		return ErrIdentityPoint
	}

	k.element = element
	return nil
}
