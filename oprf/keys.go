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

	if err := k.k.UnmarshalBinary(data); err != nil {
		return err
	}

	// RFC 9497 requires private keys (scalars) to be non-zero. A zero
	// private key produces an identity public key, which collapses the
	// (V)OPRF/POPRF relation to a publicly computable function.
	if k.k.IsZero() {
		return ErrInvalidPrivateKey
	}

	return nil
}

func (k *PublicKey) UnmarshalBinary(s Suite, data []byte) error {
	p, ok := s.(params)
	if !ok {
		return ErrInvalidSuite
	}
	k.p = p
	k.e = k.p.group.NewElement()

	// This accepts multiple encodings for the same point. Note that the
	// transcript for the zk/dleq proof re-encodes canonically, and so
	// different encodings do not change the derived output.
	if err := k.e.UnmarshalBinary(data); err != nil {
		return err
	}

	// RFC 9497 requires DeserializeElement to reject the group identity.
	// Accepting the identity public key would let a server prove a valid
	// DLEQ relation with the public witness 0, collapsing the VOPRF/POPRF
	// output to a publicly computable function of (input, info).
	if k.e.IsIdentity() {
		return ErrInvalidPublicKey
	}

	return nil
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

	// RFC 9497 requires private keys to be non-zero. Retry in the
	// negligible-probability case that a zero scalar is sampled.
	zero := p.group.NewScalar()
	privateKey := p.group.RandomScalar(rnd)
	for privateKey.IsEqual(zero) {
		privateKey = p.group.RandomScalar(rnd)
	}

	return &PrivateKey{p, privateKey, nil}, nil
}

// DeriveKey generates a private key from a 32-byte seed and an optional info string.
func DeriveKey(s Suite, mode Mode, seed, info []byte) (*PrivateKey, error) {
	const maxTries = 255
	p, ok := s.(params)
	if !ok {
		return nil, ErrInvalidSuite
	}
	if !isValidMode(mode) {
		return nil, ErrInvalidMode
	}
	if len(seed) != 32 {
		return nil, ErrInvalidSeed
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
