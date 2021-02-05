package hpke

import (
	"bytes"
	"crypto/rand"
	_ "crypto/sha256" // linking sha256 packages.
	_ "crypto/sha512" // linking sha512 packages.
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/kem"
)

type xkem struct {
	kemBase
	size int
}

func (x xkem) PrivateKeySize() int        { return x.size }
func (x xkem) SeedSize() int              { return x.size }
func (x xkem) CiphertextSize() int        { return x.size }
func (x xkem) PublicKeySize() int         { return x.size }
func (x xkem) EncapsulationSeedSize() int { return x.size }

func (x xkem) sizeDH() int { return x.size }
func (x xkem) calcDH(dh []byte, sk kem.PrivateKey, pk kem.PublicKey) error {
	PK := pk.(*xkemPubKey)
	SK := sk.(*xkemPrivKey)
	switch x.size {
	case x25519.Size:
		var ss, sKey, pKey x25519.Key
		copy(sKey[:], SK.priv)
		copy(pKey[:], PK.pub)
		if !x25519.Shared(&ss, &sKey, &pKey) {
			return errKemInvalidSharedSecret
		}
		copy(dh, ss[:])
	case x448.Size:
		var ss, sKey, pKey x448.Key
		copy(sKey[:], SK.priv)
		copy(pKey[:], PK.pub)
		if !x448.Shared(&ss, &sKey, &pKey) {
			return errKemInvalidSharedSecret
		}
		copy(dh, ss[:])
	}
	return nil
}

// Deterministicallly derives a keypair from a seed. If you're unsure,
// you're better off using GenerateKey().
//
// Panics if seed is not of length SeedSize().
func (x xkem) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	// Implementation based on
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-06.html#name-derivekeypair
	if len(seed) != x.SeedSize() {
		panic(kem.ErrSeedSize)
	}
	sk := &xkemPrivKey{scheme: x, priv: make([]byte, x.size)}
	dkpPrk := x.labeledExtract(nil, []byte("dkp_prk"), seed)
	bytes := x.labeledExpand(
		dkpPrk,
		[]byte("sk"),
		nil,
		uint16(x.PrivateKeySize()),
	)
	copy(sk.priv, bytes)
	return sk.Public(), sk
}
func (x xkem) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	sk := &xkemPrivKey{scheme: x, priv: make([]byte, x.PrivateKeySize())}
	_, err := io.ReadFull(rand.Reader, sk.priv)
	if err != nil {
		return nil, nil, err
	}
	return sk.Public(), sk, nil
}
func (x xkem) UnmarshalBinaryPrivateKey(data []byte) (kem.PrivateKey, error) {
	l := x.PrivateKeySize()
	if len(data) < l {
		return nil, errKemInvalidPrivateKey
	}
	sk := &xkemPrivKey{x, make([]byte, l), nil}
	copy(sk.priv, data[:l])
	return sk, nil
}
func (x xkem) UnmarshalBinaryPublicKey(data []byte) (kem.PublicKey, error) {
	l := x.PublicKeySize()
	if len(data) < l {
		return nil, errKemInvalidPublicKey
	}
	pk := &xkemPubKey{x, make([]byte, l)}
	copy(pk.pub, data[:l])
	return pk, nil
}

type xkemPubKey struct {
	scheme xkem
	pub    []byte
}

func (k *xkemPubKey) String() string     { return fmt.Sprintf("%x", k.pub) }
func (k *xkemPubKey) Scheme() kem.Scheme { return k.scheme }
func (k *xkemPubKey) MarshalBinary() ([]byte, error) {
	return append(make([]byte, 0, k.scheme.PublicKeySize()), k.pub...), nil
}
func (k *xkemPubKey) Equal(pk kem.PublicKey) bool {
	k1, ok := pk.(*xkemPubKey)
	return ok &&
		k.scheme.id == k1.scheme.id &&
		bytes.Equal(k.pub, k1.pub)
}
func (k *xkemPubKey) Validate() bool { return len(k.pub) == k.scheme.PublicKeySize() }

type xkemPrivKey struct {
	scheme xkem
	priv   []byte
	pub    *xkemPubKey
}

func (k *xkemPrivKey) String() string     { return fmt.Sprintf("%x", k.priv) }
func (k *xkemPrivKey) Scheme() kem.Scheme { return k.scheme }
func (k *xkemPrivKey) MarshalBinary() ([]byte, error) {
	return append(make([]byte, 0, k.scheme.PrivateKeySize()), k.priv...), nil
}
func (k *xkemPrivKey) Equal(pk kem.PrivateKey) bool {
	k1, ok := pk.(*xkemPrivKey)
	return ok &&
		k.scheme.id == k1.scheme.id &&
		subtle.ConstantTimeCompare(k.priv, k1.priv) == 1
}
func (k *xkemPrivKey) Public() kem.PublicKey {
	if k.pub == nil {
		k.pub = &xkemPubKey{scheme: k.scheme, pub: make([]byte, k.scheme.size)}
		switch k.scheme.size {
		case x25519.Size:
			var sk, pk x25519.Key
			copy(sk[:], k.priv)
			x25519.KeyGen(&pk, &sk)
			copy(k.pub.pub, pk[:])
		case x448.Size:
			var sk, pk x448.Key
			copy(sk[:], k.priv)
			x448.KeyGen(&pk, &sk)
			copy(k.pub.pub, pk[:])
		}
	}
	return k.pub
}
func (k *xkemPrivKey) Validate() bool { return len(k.priv) == k.scheme.PrivateKeySize() }
