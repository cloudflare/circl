package hpke

import (
	"bytes"
	"crypto/rand"
	_ "crypto/sha256" // linking sha256 packages.
	_ "crypto/sha512" // linking sha512 packages.
	"crypto/subtle"
	"errors"
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
	PK, ok := pk.(*xkemPubKey)
	if !ok {
		return kem.ErrTypeMismatch
	}
	SK, ok := sk.(*xkemPrivKey)
	if !ok {
		return kem.ErrTypeMismatch
	}
	switch x.size {
	case x25519.Size:
		var ss, sKey, pKey x25519.Key
		copy(sKey[:], SK.k)
		copy(pKey[:], PK.k)
		x25519.Shared(&ss, &sKey, &pKey)
		copy(dh, ss[:])
	case x448.Size:
		var ss, sKey, pKey x448.Key
		copy(sKey[:], SK.k)
		copy(pKey[:], PK.k)
		x448.Shared(&ss, &sKey, &pKey)
		copy(dh, ss[:])
	}
	return nil
}
func (x xkem) DeriveKey(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	// Implementation based on https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-06.html#name-derivekeypair
	if len(seed) != x.SeedSize() {
		panic(kem.ErrSeedSize)
	}
	sk := &xkemPrivKey{c: x, k: make([]byte, x.size)}
	dkpPrk := x.labeledExtract(nil, []byte("dkp_prk"), seed)
	bytes := x.labeledExpand(
		dkpPrk,
		[]byte("sk"),
		nil,
		uint16(x.PrivateKeySize()),
	)
	copy(sk.k, bytes)
	return sk.Public(), sk
}
func (x xkem) GenerateKey() (kem.PublicKey, kem.PrivateKey, error) {
	sk := &xkemPrivKey{c: x, k: make([]byte, x.PrivateKeySize())}
	_, err := io.ReadFull(rand.Reader, sk.k)
	if err != nil {
		return nil, nil, err
	}
	return sk.Public(), sk, nil
}
func (x xkem) UnmarshalBinaryPrivateKey(data []byte) (kem.PrivateKey, error) {
	l := x.PrivateKeySize()
	if len(data) < l {
		return nil, errors.New("invalid private key")
	}
	sk := &xkemPrivKey{x, make([]byte, l), nil}
	copy(sk.k, data[:l])
	return sk, nil
}
func (x xkem) UnmarshalBinaryPublicKey(data []byte) (kem.PublicKey, error) {
	l := x.PublicKeySize()
	if len(data) < l {
		return nil, errors.New("invalid public key")
	}
	pk := &xkemPubKey{x, make([]byte, l)}
	copy(pk.k, data[:l])
	return pk, nil
}

type xkemPubKey struct {
	c xkem
	k []byte
}

func (k *xkemPubKey) String() string     { return fmt.Sprintf("%x", k.k) }
func (k *xkemPubKey) Scheme() kem.Scheme { return k.c }
func (k *xkemPubKey) MarshalBinary() ([]byte, error) {
	return append(make([]byte, 0, k.c.PublicKeySize()), k.k...), nil
}
func (k *xkemPubKey) Equal(pk kem.PublicKey) bool {
	k1, ok := pk.(*xkemPubKey)
	return ok &&
		k.c.id == k1.c.id &&
		bytes.Equal(k.k, k1.k)
}

type xkemPrivKey struct {
	c   xkem
	k   []byte
	pub *xkemPubKey
}

func (k *xkemPrivKey) String() string     { return fmt.Sprintf("%x", k.k) }
func (k *xkemPrivKey) Scheme() kem.Scheme { return k.c }
func (k *xkemPrivKey) MarshalBinary() ([]byte, error) {
	return append(make([]byte, 0, k.c.PrivateKeySize()), k.k...), nil
}
func (k *xkemPrivKey) Equal(pk kem.PrivateKey) bool {
	k1, ok := pk.(*xkemPrivKey)
	return ok &&
		k.c.id == k1.c.id &&
		subtle.ConstantTimeCompare(k.k, k1.k) == 1
}
func (k *xkemPrivKey) Public() kem.PublicKey {
	if k.pub == nil {
		k.pub = &xkemPubKey{c: k.c, k: make([]byte, k.c.size)}
		switch k.c.size {
		case x25519.Size:
			var sk, pk x25519.Key
			copy(sk[:], k.k)
			x25519.KeyGen(&pk, &sk)
			copy(k.pub.k, pk[:])
		case x448.Size:
			var sk, pk x448.Key
			copy(sk[:], k.k)
			x448.KeyGen(&pk, &sk)
			copy(k.pub.k, pk[:])
		}
	}
	return k.pub
}
