package xkem

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/kem"
)

type xkemPubKey struct {
	c xkem
	k []byte
}

func (k xkemPubKey) String() string     { return fmt.Sprintf("%x", k.k) }
func (k xkemPubKey) Scheme() kem.Scheme { return k.c }
func (k xkemPubKey) MarshalBinary() ([]byte, error) {
	return append(make([]byte, 0, k.c.size), k.k...), nil
}
func (k xkemPubKey) Equal(pk kem.PublicKey) bool {
	k1, ok := pk.(xkemPubKey)
	return ok && k.c.id == k1.c.id && bytes.Equal(k.k, k1.k)
}

type xkemPrivKey struct {
	c   xkem
	k   []byte
	pub *xkemPubKey
}

func (k xkemPrivKey) String() string     { return fmt.Sprintf("%x", k.k) }
func (k xkemPrivKey) Scheme() kem.Scheme { return k.c }
func (k xkemPrivKey) MarshalBinary() ([]byte, error) {
	return append(make([]byte, 0, k.c.size), k.k...), nil
}
func (k xkemPrivKey) Equal(pk kem.PrivateKey) bool {
	k1, ok := pk.(xkemPrivKey)
	return ok && k.c.id == k1.c.id && subtle.ConstantTimeCompare(k.k, k1.k) == 0
}
func (k *xkemPrivKey) Public() xkemPubKey {
	if k.pub == nil {
		k.pub = &xkemPubKey{c: k.c, k: make([]byte, k.c.size)}
		switch k.c.id {
		case KemX25519Sha256:
			var sk, pk x25519.Key
			copy(sk[:], k.k)
			x25519.KeyGen(&pk, &sk)
			copy(k.pub.k, pk[:])
		case KemX448Sha512:
			var sk, pk x448.Key
			copy(sk[:], k.k)
			x448.KeyGen(&pk, &sk)
			copy(k.pub.k, pk[:])
		}
	}
	return *k.pub
}

func (x xkem) UnmarshalBinaryPrivateKey(data []byte) (kem.PrivateKey, error) {
	l := x.PrivateKeySize()
	if len(data) < l {
		return nil, errors.New("invalid private key")
	}
	sk := xkemPrivKey{x, make([]byte, l), nil}
	copy(sk.k, data[:l])
	return sk, nil
}

func (x xkem) UnmarshalBinaryPublicKey(data []byte) (kem.PublicKey, error) {
	l := x.PublicKeySize()
	if len(data) < l {
		return nil, errors.New("invalid public key")
	}
	pk := xkemPubKey{x, make([]byte, l)}
	copy(pk.k, data[:l])
	return pk, nil
}

func (x xkem) DeriveKey(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	if len(seed) != x.SeedSize() {
		panic(kem.ErrSeedSize)
	}
	sk := xkemPrivKey{c: x, k: make([]byte, x.size)}
	dkpPrk := x.labeledExtract(nil, []byte("dkp_prk"), seed)
	bytes := x.labeledExpand(dkpPrk, []byte("sk"), nil, uint16(x.PrivateKeySize()))
	copy(sk.k, bytes)
	return sk.Public(), sk
}

func (x xkem) GenerateKey() (kem.PublicKey, kem.PrivateKey, error) {
	sk := xkemPrivKey{c: x, k: make([]byte, x.size)}
	_, err := io.ReadFull(rand.Reader, sk.k)
	if err != nil {
		return nil, nil, err
	}
	return sk.Public(), sk, nil
}
