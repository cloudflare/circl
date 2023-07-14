// Package bls provides BLS signatures using the BLS12-381 pairing curve.
//
// This packages implements the IETF/CFRG draft for BLS signatures [1].
// Currently only the BASIC mode (one of the three modes specified
// in the draft) is supported. The pairing function is instantiated
// with the BLS12-381 curve.
//
// # Groups
//
// The BLS signature scheme can be instantiated with keys in one of the
// two groups: G1 or G2, which correspond to the input domain of a pairing
// function e(G1,G2) -> Gt.
// Thus, choosing keys in G1 implies that signature values are internally
// represented in G2; or viceversa. Use the types KeyG1SigG2 or KeyG2SigG1
// to express this preference.
//
// # Serialization
//
// The serialization of elements in G1 and G2 follows the recommendation
// given in [2], in order to be compatible with other implementations of
// BLS12-381 curve.
//
// # References
//
// [1] https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05
//
// [2] https://github.com/zkcrypto/bls12_381/blob/0.7.0/src/notes/serialization.rs
package bls

import (
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	GG "github.com/cloudflare/circl/ecc/bls12381"
	"golang.org/x/crypto/hkdf"
)

var (
	ErrInvalid    = errors.New("bls: invalid BLS instance")
	ErrInvalidKey = errors.New("bls: invalid key")
	ErrKeyGen     = errors.New("bls: too many unsuccessful key generation tries")
	ErrShortIKM   = errors.New("bls: IKM material shorter than 32 bytes")
	ErrAggregate  = errors.New("bls: error while aggregating signatures")
)

const (
	dstG1 = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
	dstG2 = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
)

type Signature = []byte

type (
	// G1 group used for keys defined in pairing group G1.
	G1 struct{ g GG.G1 }
	// G2 group used for keys defined in pairing group G2.
	G2 struct{ g GG.G2 }
	// KeyG1SigG2 sets the keys to G1 and signatures to G2.
	KeyG1SigG2 = G1
	// KeyG2SigG1 sets the keys to G2 and signatures to G1.
	KeyG2SigG1 = G2
)

func (f *G1) setBytes(b []byte) error { return f.g.SetBytes(b) }
func (f *G2) setBytes(b []byte) error { return f.g.SetBytes(b) }

func (f *G1) hash(msg []byte) { f.g.Hash(msg, []byte(dstG1)) }
func (f *G2) hash(msg []byte) { f.g.Hash(msg, []byte(dstG2)) }

// KeyGroup determines the group used for keys, while the other
// group is used for signatures.
type KeyGroup interface{ G1 | G2 }

type PrivateKey[K KeyGroup] struct {
	key GG.Scalar
	pub *PublicKey[K]
}

type PublicKey[K KeyGroup] struct{ key K }

func (k *PrivateKey[K]) Public() crypto.PublicKey { return k.PublicKey() }

// PublicKey computes the corresponding public key. The key is cached
// for further invocations to this function.
func (k *PrivateKey[K]) PublicKey() *PublicKey[K] {
	if k.pub == nil {
		k.pub = new(PublicKey[K])
		switch any(k).(type) {
		case *PrivateKey[G1]:
			kk := any(&k.pub.key).(*G1)
			kk.g.ScalarMult(&k.key, GG.G1Generator())
		case *PrivateKey[G2]:
			kk := any(&k.pub.key).(*G2)
			kk.g.ScalarMult(&k.key, GG.G2Generator())
		default:
			panic(ErrInvalid)
		}
	}

	return k.pub
}

func (k *PrivateKey[K]) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey[K])
	if !ok {
		return false
	}

	switch any(k).(type) {
	case *PrivateKey[G1], *PrivateKey[G2]:
		return k.key.IsEqual(&xx.key) == 1
	default:
		panic(ErrInvalid)
	}
}

// Validate explicitly determines if a private key is valid.
func (k *PrivateKey[K]) Validate() bool {
	switch any(k).(type) {
	case *PrivateKey[G1], *PrivateKey[G2]:
		return k.key.IsZero() == 0
	default:
		panic(ErrInvalid)
	}
}

// MarshalBinary returns a slice with the representation of
// the underlying PrivateKey scalar (in big-endian order).
func (k *PrivateKey[K]) MarshalBinary() ([]byte, error) {
	switch any(k).(type) {
	case *PrivateKey[G1], *PrivateKey[G2]:
		return k.key.MarshalBinary()
	default:
		panic(ErrInvalid)
	}
}

func (k *PrivateKey[K]) UnmarshalBinary(data []byte) error {
	switch any(k).(type) {
	case *PrivateKey[G1], *PrivateKey[G2]:
		if err := k.key.UnmarshalBinary(data); err != nil {
			return err
		}
		if !k.Validate() {
			return ErrInvalidKey
		}
		k.pub = nil
		return nil
	default:
		panic(ErrInvalid)
	}
}

// Validate explicitly determines if a public key is valid.
func (k *PublicKey[K]) Validate() bool {
	switch any(k).(type) {
	case *PublicKey[G1]:
		kk := any(k.key).(G1)
		return !kk.g.IsIdentity() && kk.g.IsOnG1()
	case *PublicKey[G2]:
		kk := any(k.key).(G2)
		return !kk.g.IsIdentity() && kk.g.IsOnG2()
	default:
		panic(ErrInvalid)
	}
}

func (k *PublicKey[K]) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey[K])
	if !ok {
		return false
	}

	switch any(k).(type) {
	case *PublicKey[G1]:
		xxx := any(xx.key).(G1)
		kk := any(k.key).(G1)
		return kk.g.IsEqual(&xxx.g)
	case *PublicKey[G2]:
		xxx := any(xx.key).(G2)
		kk := any(k.key).(G2)
		return kk.g.IsEqual(&xxx.g)
	default:
		panic(ErrInvalid)
	}
}

// MarshalBinary returns a slice with the compressed
// representation of the underlying element in G1 or G2.
func (k *PublicKey[K]) MarshalBinary() ([]byte, error) {
	switch any(k).(type) {
	case *PublicKey[G1]:
		kk := any(k.key).(G1)
		return kk.g.BytesCompressed(), nil
	case *PublicKey[G2]:
		kk := any(k.key).(G2)
		return kk.g.BytesCompressed(), nil
	default:
		panic(ErrInvalid)
	}
}

func (k *PublicKey[K]) UnmarshalBinary(data []byte) error {
	switch any(k).(type) {
	case *PublicKey[G1]:
		kk := any(&k.key).(*G1)
		return kk.setBytes(data)
	case *PublicKey[G2]:
		kk := any(&k.key).(*G2)
		return kk.setBytes(data)
	default:
		panic(ErrInvalid)
	}
}

// KeyGen derives a private key for the specified group (G1 or G2).
// The length of ikm material should be at least 32 bytes length.
// The salt value should be either empty or a uniformly random
// bytes whose length equals the output length of SHA-256.
func KeyGen[K KeyGroup](ikm, salt, keyInfo []byte) (*PrivateKey[K], error) {
	// Implements recommended method at:
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#name-keygen
	if len(ikm) < 32 {
		return nil, ErrShortIKM
	}

	ikmZero := make([]byte, len(ikm)+1)
	keyInfoTwo := make([]byte, len(keyInfo)+2)
	copy(ikmZero, ikm)
	copy(keyInfoTwo, keyInfo)
	const L = uint16(48)
	binary.BigEndian.PutUint16(keyInfoTwo[len(keyInfo):], L)
	OKM := make([]byte, L)

	var ss GG.Scalar
	for tries := 8; tries > 0; tries-- {
		rd := hkdf.New(sha256.New, ikmZero, salt, keyInfoTwo)
		n, err := io.ReadFull(rd, OKM)
		if n != len(OKM) || err != nil {
			return nil, err
		}

		ss.SetBytes(OKM)

		if ss.IsZero() == 1 {
			digest := sha256.Sum256(salt)
			salt = digest[:]
		} else {
			return &PrivateKey[K]{key: ss, pub: nil}, nil
		}
	}

	return nil, ErrKeyGen
}

// Sign computes a signature of a message using a key (defined in
// G1 or G1).
func Sign[K KeyGroup](k *PrivateKey[K], msg []byte) Signature {
	if !k.Validate() {
		panic(ErrInvalidKey)
	}

	switch any(k).(type) {
	case *PrivateKey[G1]:
		var Q GG.G2
		Q.Hash(msg, []byte(dstG2))
		Q.ScalarMult(&k.key, &Q)
		return Q.BytesCompressed()
	case *PrivateKey[G2]:
		var Q GG.G1
		Q.Hash(msg, []byte(dstG1))
		Q.ScalarMult(&k.key, &Q)
		return Q.BytesCompressed()
	default:
		panic(ErrInvalid)
	}
}

// Verify returns true if the signature of a message is valid for the
// corresponding public key.
func Verify[K KeyGroup](pub *PublicKey[K], msg []byte, sig Signature) bool {
	var (
		a, b interface {
			setBytes([]byte) error
			hash([]byte)
		}
		listG1 [2]*GG.G1
		listG2 [2]*GG.G2
	)

	switch any(pub).(type) {
	case *PublicKey[G1]:
		aa, bb := new(G2), new(G2)
		a, b = aa, bb
		k := any(pub.key).(G1)
		listG1[0], listG1[1] = &k.g, GG.G1Generator()
		listG2[0], listG2[1] = &aa.g, &bb.g
	case *PublicKey[G2]:
		aa, bb := new(G1), new(G1)
		a, b = aa, bb
		k := any(pub.key).(G2)
		listG2[0], listG2[1] = &k.g, GG.G2Generator()
		listG1[0], listG1[1] = &aa.g, &bb.g
	default:
		panic(ErrInvalid)
	}

	err := b.setBytes(sig)
	if err != nil {
		return false
	}
	if !pub.Validate() {
		return false
	}
	a.hash(msg)

	res := GG.ProdPairFrac(listG1[:], listG2[:], []int{1, -1})
	return res.IsIdentity()
}

// Aggregate produces a unified signature given a list of signatures.
// To specify the group of keys pass either G1{} or G2{} as the first
// parameter.
func Aggregate[K KeyGroup](k K, sigs []Signature) (Signature, error) {
	if len(sigs) == 0 {
		return nil, ErrAggregate
	}

	switch any(k).(type) {
	case G1:
		var P, Q GG.G2
		P.SetIdentity()
		for _, sig := range sigs {
			if err := Q.SetBytes(sig); err != nil {
				return nil, err
			}
			P.Add(&P, &Q)
		}
		return P.BytesCompressed(), nil

	case G2:
		var P, Q GG.G1
		P.SetIdentity()
		for _, sig := range sigs {
			if err := Q.SetBytes(sig); err != nil {
				return nil, err
			}
			P.Add(&P, &Q)
		}
		return P.BytesCompressed(), nil

	default:
		panic(ErrInvalid)
	}
}

// VerifyAggregate returns true if the aggregated signature is valid for
// the list of messages and public keys provided. The slices must have
// equal size and have at least one element.
func VerifyAggregate[K KeyGroup](pubs []*PublicKey[K], msgs [][]byte, aggSig Signature) bool {
	if len(pubs) != len(msgs) || len(pubs) == 0 {
		return false
	}

	for _, p := range pubs {
		if !p.Validate() {
			return false
		}
	}

	n := len(pubs)
	listG1 := make([]*GG.G1, n+1)
	listG2 := make([]*GG.G2, n+1)
	listSigns := make([]int, n+1)

	listG1[n] = GG.G1Generator()
	listG2[n] = GG.G2Generator()
	listSigns[n] = -1

	switch any(pubs).(type) {
	case []*PublicKey[G1]:
		for i := range msgs {
			listG2[i] = new(GG.G2)
			listG2[i].Hash(msgs[i], []byte(dstG2))

			xP := any(pubs[i].key).(G1)
			listG1[i] = &xP.g
			listSigns[i] = 1
		}

		err := listG2[n].SetBytes(aggSig)
		if err != nil {
			return false
		}

	case []*PublicKey[G2]:
		for i := range msgs {
			listG1[i] = new(GG.G1)
			listG1[i].Hash(msgs[i], []byte(dstG1))

			xP := any(pubs[i].key).(G2)
			listG2[i] = &xP.g
			listSigns[i] = 1
		}

		err := listG1[n].SetBytes(aggSig)
		if err != nil {
			return false
		}

	default:
		panic(ErrInvalid)
	}

	C := GG.ProdPairFrac(listG1, listG2, listSigns)
	return C.IsIdentity()
}
