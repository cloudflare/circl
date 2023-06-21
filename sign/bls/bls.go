// Package bls provides BLS signatures instantiated with the BLS12-381 pairing curve.
package bls

import (
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"

	GG "github.com/cloudflare/circl/ecc/bls12381"
	"golang.org/x/crypto/hkdf"
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

func (k *PrivateKey[K]) PublicKey() *PublicKey[K] {
	if k.pub == nil {
		k.pub = new(PublicKey[K])
		switch (interface{})(k).(type) {
		case *PrivateKey[G1]:
			kk := (interface{})(&k.pub.key).(*G1)
			kk.g.ScalarMult(&k.key, GG.G1Generator())
		case *PrivateKey[G2]:
			kk := (interface{})(&k.pub.key).(*G2)
			kk.g.ScalarMult(&k.key, GG.G2Generator())
		default:
			panic(ErrInvalid)
		}
	}

	return k.pub
}

func (k *PrivateKey[K]) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey[K])
	switch (interface{})(k).(type) {
	case *PrivateKey[G1], *PrivateKey[G2]:
		return ok && k.key.IsEqual(&xx.key) == 1
	default:
		panic(ErrInvalid)
	}
}

func (k *PrivateKey[K]) UnmarshalBinary(data []byte) error {
	switch (interface{})(k).(type) {
	case *PrivateKey[G1], *PrivateKey[G2]:
		return k.key.UnmarshalBinary(data)
	default:
		panic(ErrInvalid)
	}
}

func (k *PublicKey[K]) Validate() bool {
	switch (interface{})(k).(type) {
	case *PublicKey[G1]:
		kk := (interface{})(k.key).(G1)
		return !kk.g.IsIdentity() && kk.g.IsOnG1()
	case *PublicKey[G2]:
		kk := (interface{})(k.key).(G2)
		return !kk.g.IsIdentity() && kk.g.IsOnG2()
	default:
		panic(ErrInvalid)
	}
}

func (k *PublicKey[K]) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey[K])
	switch (interface{})(k).(type) {
	case *PublicKey[G1]:
		xxx := (interface{})(xx.key).(G1)
		kk := (interface{})(k.key).(G1)
		return ok && kk.g.IsEqual(&xxx.g)
	case *PublicKey[G2]:
		xxx := (interface{})(xx.key).(G1)
		kk := (interface{})(k.key).(G1)
		return ok && kk.g.IsEqual(&xxx.g)
	default:
		panic(ErrInvalid)
	}
}

func KeyGen[K KeyGroup](ikm, salt, keyInfo []byte) (*PrivateKey[K], error) {
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

func Sign[K KeyGroup](k *PrivateKey[K], msg []byte) Signature {
	switch (interface{})(k).(type) {
	case *PrivateKey[G1]:
		var Q G2
		Q.hash(msg)
		Q.g.ScalarMult(&k.key, &Q.g)
		return Q.g.BytesCompressed()
	case *PrivateKey[G2]:
		var Q G1
		Q.hash(msg)
		Q.g.ScalarMult(&k.key, &Q.g)
		return Q.g.BytesCompressed()
	default:
		panic(ErrInvalid)
	}
}

func Verify[K KeyGroup](pub *PublicKey[K], msg []byte, sig Signature) bool {
	var (
		a, b interface {
			setBytes([]byte) error
			hash([]byte)
		}
		listG1 [2]*GG.G1
		listG2 [2]*GG.G2
	)

	switch (interface{})(pub).(type) {
	case *PublicKey[G1]:
		aa, bb := new(G2), new(G2)
		a, b = aa, bb
		k := (interface{})(pub.key).(G1)
		listG1[0], listG1[1] = &k.g, GG.G1Generator()
		listG2[0], listG2[1] = &aa.g, &bb.g
	case *PublicKey[G2]:
		aa, bb := new(G1), new(G1)
		a, b = aa, bb
		k := (interface{})(pub.key).(G2)
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

func Aggregate[K KeyGroup](sigs []Signature) (Signature, error) {
	if len(sigs) == 0 {
		return nil, ErrAggregate
	}

	return nil, nil
	// switch (interface{})(Aggregate[K]).(type) {
	// case *func([]Signature) (Signature, error):
	// 	var P, Q GG.G2
	// 	P.SetIdentity()
	// 	for _, sig := range sigs {
	// 		if err := Q.SetBytes(sig); err != nil {
	// 			return nil, err
	// 		}
	// 		P.Add(&P, &Q)
	// 	}
	// 	return P.BytesCompressed(), nil

	// case *func([]Signature) (Signature, error):
	// 	var P, Q GG.G1
	// 	P.SetIdentity()
	// 	for _, sig := range sigs {
	// 		if err := Q.SetBytes(sig); err != nil {
	// 			return nil, err
	// 		}
	// 		P.Add(&P, &Q)
	// 	}
	// 	return P.BytesCompressed(), nil

	// default:
	// 	panic(ErrInvalid)
	// }
}

func VerifyAggregate[K KeyGroup](pubs []PublicKey[K], msgs [][]byte, sig Signature) bool {
	if len(pubs) != len(msgs) || len(pubs) == 0 || len(msgs) == 0 {
		return false
	}

	setMsgs := make(map[string][]PublicKey[K], len(pubs))
	switch (interface{})(pubs).(type) {
	case []PublicKey[G1]:
		for i := range msgs {
			s := hex.EncodeToString(msgs[i])
			setMsgs[s] = append(setMsgs[s], pubs[i])
		}
		return false

	case []PublicKey[G2]:
		return false

	default:
		panic(ErrInvalid)
	}
}

var (
	ErrInvalid   = errors.New("bls: invalid BLS instance")
	ErrKeyGen    = errors.New("bls: too many unsuccessful key generation tries")
	ErrShortIKM  = errors.New("bls: IKM material shorter than 32 bytes")
	ErrAggregate = errors.New("bls: error while aggregating signatures")
)

const (
	dstG1 = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
	dstG2 = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
)
