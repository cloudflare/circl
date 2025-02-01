package slhdsa

import (
	"bytes"
	"crypto"
	"crypto/subtle"

	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/sign"
	"golang.org/x/crypto/cryptobyte"
)

// [PrivateKey] stores a private key of the SLH-DSA scheme.
// It implements the [crypto.Signer] and [crypto.PrivateKey] interfaces.
// For serialization, it also implements [cryptobyte.MarshalingValue],
// [encoding.BinaryMarshaler], and [encoding.BinaryUnmarshaler].
type PrivateKey struct {
	ParamID      ParamID
	seed, prfKey []byte
	publicKey    PublicKey
}

func (p *params) PrivateKeySize() uint32 { return 2*p.n + p.PublicKeySize() }

// Marshal serializes the key using a Builder.
func (k PrivateKey) Marshal(b *cryptobyte.Builder) error {
	b.AddBytes(k.seed)
	b.AddBytes(k.prfKey)
	b.AddValue(k.publicKey)
	return nil
}

// Unmarshal recovers a PrivateKey from a [cryptobyte.String]. Caller must
// specify the ParamID of the key in advance.
// Example:
//
//	var key PrivateKey
//	key.ParamID = ParamIDSHA2Small192
//	key.Unmarshal(str) // returns true
func (k *PrivateKey) Unmarshal(s *cryptobyte.String) bool {
	params := k.ParamID.params()
	var b []byte
	if !s.ReadBytes(&b, int(params.PrivateKeySize())) {
		return false
	}

	c := cursor(b)
	return k.fromBytes(params, &c)
}

func (k *PrivateKey) fromBytes(p *params, c *cursor) bool {
	k.ParamID = p.id
	k.seed = c.Next(p.n)
	k.prfKey = c.Next(p.n)
	return k.publicKey.fromBytes(p, c)
}

// UnmarshalBinary recovers a PrivateKey from a slice of bytes. Caller must
// specify the ParamID of the key in advance.
// Example:
//
//	var key PrivateKey
//	key.ParamID = ParamIDSHA2Small192
//	key.UnmarshalBinary(bytes) // returns nil
func (k *PrivateKey) UnmarshalBinary(b []byte) error { return conv.UnmarshalBinary(k, b) }
func (k PrivateKey) MarshalBinary() ([]byte, error)  { return conv.MarshalBinary(k) }
func (k PrivateKey) Scheme() sign.Scheme             { return scheme{k.ParamID} }
func (k PrivateKey) Public() crypto.PublicKey        { pk := k.PublicKey(); return &pk }
func (k PrivateKey) PublicKey() (out PublicKey) {
	params := k.ParamID.params()
	c := cursor(make([]byte, params.PublicKeySize()))
	out.fromBytes(params, &c)
	copy(out.seed, k.publicKey.seed)
	copy(out.root, k.publicKey.root)
	return
}

func (k PrivateKey) Equal(x crypto.PrivateKey) bool {
	other, ok := x.(PrivateKey)
	return ok && k.ParamID == other.ParamID &&
		subtle.ConstantTimeCompare(k.seed, other.seed) == 1 &&
		subtle.ConstantTimeCompare(k.prfKey, other.prfKey) == 1 &&
		k.publicKey.Equal(&other.publicKey)
}

// [PublicKey] stores a public key of the SLH-DSA scheme.
// It implements the [crypto.PublicKey] interface.
// For serialization, it also implements [cryptobyte.MarshalingValue],
// [encoding.BinaryMarshaler], and [encoding.BinaryUnmarshaler].
type PublicKey struct {
	ParamID    ParamID
	seed, root []byte
}

func (p *params) PublicKeySize() uint32 { return 2 * p.n }

// Marshal serializes the key using a Builder.
func (k PublicKey) Marshal(b *cryptobyte.Builder) error {
	b.AddBytes(k.seed)
	b.AddBytes(k.root)
	return nil
}

// Unmarshal recovers a PublicKey from a [cryptobyte.String]. Caller must
// specify the ParamID of the key in advance.
// Example:
//
//	var key PublicKey
//	key.ParamID = ParamIDSHA2Small192
//	key.Unmarshal(str) // returns true
func (k *PublicKey) Unmarshal(s *cryptobyte.String) bool {
	params := k.ParamID.params()
	var b []byte
	if !s.ReadBytes(&b, int(params.PublicKeySize())) {
		return false
	}

	c := cursor(b)
	return k.fromBytes(params, &c)
}

func (k *PublicKey) fromBytes(p *params, c *cursor) bool {
	k.ParamID = p.id
	k.seed = c.Next(p.n)
	k.root = c.Next(p.n)
	return len(*c) == 0
}

// UnmarshalBinary recovers a PublicKey from a slice of bytes. Caller must
// specify the ParamID of the key in advance.
// Example:
//
//	var key PublicKey
//	key.ParamID = ParamIDSHA2Small192
//	key.UnmarshalBinary(bytes) // returns nil
func (k *PublicKey) UnmarshalBinary(b []byte) error { return conv.UnmarshalBinary(k, b) }
func (k PublicKey) MarshalBinary() ([]byte, error)  { return conv.MarshalBinary(k) }
func (k PublicKey) Scheme() sign.Scheme             { return scheme{k.ParamID} }
func (k PublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*PublicKey)
	return ok && k.ParamID == other.ParamID &&
		bytes.Equal(k.seed, other.seed) &&
		bytes.Equal(k.root, other.root)
}
