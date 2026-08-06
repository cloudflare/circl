package bbs

import (
	"crypto"
	"math"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/internal/conv"
	"golang.org/x/crypto/cryptobyte"
)

// PrivateKey represents a private key for signing.
type PrivateKey struct {
	pub *PublicKey
	key bufScalar
}

func (k *PrivateKey) Public() crypto.PublicKey { return k.PublicKey() }

func (k *PrivateKey) PublicKey() *PublicKey {
	k.calcPublicKey()
	pubCopy := *k.pub
	return &pubCopy
}

func (k *PrivateKey) calcPublicKey() {
	if k.pub == nil {
		k.pub = new(PublicKey)
		k.pub.key.ScalarMult(&k.key.scalar, bls12381.G2Generator())
		k.pub.encoded = [g2Size]byte(k.pub.key.BytesCompressed())
	}
}

func (k *PrivateKey) Equal(x crypto.PrivateKey) bool {
	kx, ok := x.(*PrivateKey)
	return ok && k.key.scalar.IsEqual(&kx.key.scalar) == 1
}

func (k *PrivateKey) MarshalBinary() ([]byte, error)      { return conv.MarshalBinaryLen(k, PrivateKeySize) }
func (k *PrivateKey) UnmarshalBinary(b []byte) error      { return conv.UnmarshalBinary(k, b) }
func (k *PrivateKey) Marshal(b *cryptobyte.Builder) error { b.AddValue(&k.key); return nil }
func (k *PrivateKey) Unmarshal(s *cryptobyte.String) bool { return k.key.Unmarshal(s) }

// PublicKey represents a public key for verification of signatures and proofs.
type PublicKey struct {
	key     g2
	encoded [PublicKeySize]byte
}

func (k *PublicKey) Equal(x crypto.PublicKey) bool {
	kx, ok := x.(*PublicKey)
	return ok && k.key.IsEqual(&kx.key)
}
func (k *PublicKey) MarshalBinary() ([]byte, error)      { return conv.MarshalBinaryLen(k, PublicKeySize) }
func (k *PublicKey) UnmarshalBinary(b []byte) error      { return conv.UnmarshalBinary(k, b) }
func (k *PublicKey) Marshal(b *cryptobyte.Builder) error { b.AddBytes(k.encoded[:]); return nil }
func (k *PublicKey) Unmarshal(s *cryptobyte.String) bool {
	var b [PublicKeySize]byte
	ok := s.CopyBytes(b[:]) && k.key.SetBytes(b[:]) == nil
	if ok {
		k.encoded = b
	}
	return ok
}

// KeyGen returns a [PrivateKey] derived from random key material of at least
// [KeyMaterialMinSize] bytes.
// Key information is used to derive multiple keys from the same key material.
// Optionally, a domain separation tag can be provided.
// Returns an error if keyMaterial is shorter than [KeyMaterialMinSize] bytes,
// or if the length of info is larger than [math.MaxUint16].
func KeyGen(id SuiteID, keyMaterial, info, dst []byte) (*PrivateKey, error) {
	if len(keyMaterial) < KeyMaterialMinSize {
		return nil, ErrKeyMaterial
	}

	if len(info) > math.MaxUint16 {
		return nil, ErrKeyInfo
	}

	s := id.new()
	if dst == nil {
		dst = s.keyDST()
	}

	bLen := len(keyMaterial) + 2 + len(info)
	b := cryptobyte.NewFixedBuilder(make([]byte, 0, bLen))
	b.AddBytes(keyMaterial)
	b.AddUint16(uint16(len(info)))
	b.AddBytes(info)
	input, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	return &PrivateKey{key: s.hashToScalar(input, dst), pub: nil}, nil
}
