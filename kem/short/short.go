// Package short implements KEM based on a short Weierstrass curve and HDKF
// as key derivation fuunction.
package short

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	_ "crypto/sha256" // to link
	_ "crypto/sha512" // to link
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/hkdf"
)

type KemID uint

const (
	P256hkdfsha256 KemID = iota + 0x0010
	P384hkdfsha384
	P521hkdfsha512
)

// New returns a KEM based on short Weierstrass curves and HKDF as key derivation function.
func New(id KemID, prefix []byte) kem.Scheme {
	switch id {
	case P256hkdfsha256:
		return short{elliptic.P256().Params(), id, crypto.SHA256, prefix}
	case P384hkdfsha384:
		return short{elliptic.P384().Params(), id, crypto.SHA384, prefix}
	case P521hkdfsha512:
		return short{elliptic.P521().Params(), id, crypto.SHA512, prefix}
	default:
		panic("wrong KemID")
	}
}

type short struct {
	*elliptic.CurveParams
	id     KemID
	h      crypto.Hash
	prefix []byte
}

func (s short) Name() string               { return s.CurveParams.Name }
func (s short) SharedKeySize() int         { return (s.BitSize + 7) / 8 }
func (s short) PrivateKeySize() int        { return (s.BitSize + 7) / 8 }
func (s short) SeedSize() int              { return (s.BitSize + 7) / 8 }
func (s short) CiphertextSize() int        { l := (s.BitSize + 7) / 8; return 1 + 2*l }
func (s short) PublicKeySize() int         { l := (s.BitSize + 7) / 8; return 1 + 2*l }
func (s short) EncapsulationSeedSize() int { return s.SeedSize() }

func (s short) GenerateKey() (kem.PublicKey, kem.PrivateKey, error) {
	sk, x, y, err := elliptic.GenerateKey(s, cryptoRand.Reader)
	return shortPubKey{s, x, y}, shortPrivKey{s, sk}, err
}

func (s short) Encapsulate(pk kem.PublicKey) (ct []byte, ss []byte) {
	pkR, ok := pk.(shortPubKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}

	pkE, skE, err := s.GenerateKey()
	if err != nil {
		panic(err)
	}

	x, _ := s.ScalarMult(pkR.x, pkR.y, skE.(shortPrivKey).k)
	dh := make([]byte, s.SharedKeySize())
	copy(dh, x.Bytes())
	enc, err := pkE.MarshalBinary()
	if err != nil {
		panic(err)
	}
	pkRm, err := pkR.MarshalBinary()
	if err != nil {
		panic(err)
	}
	kemCtx := append(enc, pkRm...)
	ss = s.extractExpand(dh, kemCtx)
	return enc, ss
}

func (s short) getSuiteID() (sid [5]byte) {
	copy(sid[:], "KEM")
	binary.BigEndian.PutUint16(sid[3:5], uint16(s.id))
	return
}

func (s short) extractExpand(dh, kemCtx []byte) []byte {
	eaePkr := s.labeledExtract(nil, []byte("eae_prk"), dh)
	return s.labeledExpand(eaePkr, []byte("shared_secret"), kemCtx)
}

func (s short) labeledExtract(salt, label, info []byte) []byte {
	suiteID := s.getSuiteID()
	labeledIKM := make([]byte, 0, len(s.prefix)+len(suiteID)+len(label)+len(info))
	labeledIKM = append(labeledIKM, s.prefix...)
	labeledIKM = append(labeledIKM, suiteID[:]...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, info...)
	return hkdf.Extract(s.h.New, labeledIKM, salt)
}

func (s short) labeledExpand(prk, label, info []byte) []byte {
	suiteID := s.getSuiteID()
	l := s.h.Size()
	labeledInfo := make([]byte, 2, 2+len(s.prefix)+len(suiteID)+len(label)+len(info))
	binary.BigEndian.PutUint16(labeledInfo[0:2], uint16(l))
	labeledInfo = append(labeledInfo, s.prefix...)
	labeledInfo = append(labeledInfo, suiteID[:]...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)
	b := make([]byte, l)
	rd := hkdf.Expand(s.h.New, prk, labeledInfo)
	_, _ = io.ReadFull(rd, b)
	return b
}

func (s short) Decapsulate(sk kem.PrivateKey, ct []byte) []byte {
	pk, err := s.UnmarshalBinaryPublicKey(ct)
	if err != nil {
		panic(err)
	}
	pkE := pk.(shortPubKey)
	skR, ok := sk.(shortPrivKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}
	x, _ := s.ScalarMult(pkE.x, pkE.y, skR.k)
	dh := make([]byte, s.SharedKeySize())
	copy(dh, x.Bytes())

	pkR := skR.Public()
	pkRm, err := pkR.MarshalBinary()
	if err != nil {
		panic(err)
	}
	kemCtx := append(ct, pkRm...)
	return s.extractExpand(dh, kemCtx)
}

func (s short) UnmarshalBinaryPublicKey(data []byte) (kem.PublicKey, error) {
	x, y := elliptic.Unmarshal(s, data)
	if x == nil {
		return nil, errors.New("invalid public key")
	}
	return shortPubKey{s, x, y}, nil
}

func (s short) UnmarshalBinaryPrivateKey(data []byte) (kem.PrivateKey, error) {
	return shortPrivKey{s, data}, nil
}

func (s short) DeriveKey(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	var bitmask = byte(0xFF)
	if s.BitSize == 521 {
		bitmask = 0x01
	}

	dkpPrk := s.labeledExtract(nil, []byte("dkp_prk"), seed)
	var skBig big.Int
	ctr := 0
	for skBig.Sign() == 0 || skBig.Cmp(s.N) >= 0 {
		if ctr > 255 {
			panic("derive key error")
		}
		bytes := s.labeledExpand(dkpPrk, []byte("candidate"), []byte{byte(ctr)})
		bytes[0] &= bitmask
		skBig.SetBytes(bytes)
		ctr++
	}
	k := make([]byte, s.PrivateKeySize())
	copy(k, skBig.Bytes())
	sk := shortPrivKey{s, k}
	return sk.Public(), sk
}

func (s short) EncapsulateDeterministically(pk kem.PublicKey, seed []byte) (ct, ss []byte) {
	if len(seed) != s.SeedSize() {
		panic(kem.ErrSeedSize)
	}

	pkR, ok := pk.(shortPubKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}

	pkE, skE := s.DeriveKey(seed)

	x, _ := s.ScalarMult(pkR.x, pkR.y, skE.(shortPrivKey).k)
	dh := make([]byte, s.SharedKeySize())
	copy(dh, x.Bytes())
	enc, err := pkE.MarshalBinary()
	if err != nil {
		panic(err)
	}
	pkRm, err := pkR.MarshalBinary()
	if err != nil {
		panic(err)
	}
	kemCtx := append(enc, pkRm...)
	ss = s.extractExpand(dh, kemCtx)
	return enc, ss
}

type shortPubKey struct {
	c    short
	x, y *big.Int
}

func (k shortPubKey) Scheme() kem.Scheme             { return k.c }
func (k shortPubKey) MarshalBinary() ([]byte, error) { return elliptic.Marshal(k.c, k.x, k.y), nil }
func (k shortPubKey) Equal(pk kem.PublicKey) bool {
	k1, ok := pk.(shortPubKey)
	return ok && k.c.Params() == k1.c.Params() && k.x.Cmp(k1.x) == 0 && k.y.Cmp(k1.y) == 0
}

type shortPrivKey struct {
	c short
	k []byte
}

func (k shortPrivKey) Scheme() kem.Scheme             { return k.c }
func (k shortPrivKey) MarshalBinary() ([]byte, error) { return k.k, nil }
func (k shortPrivKey) Equal(pk kem.PrivateKey) bool {
	k1, ok := pk.(shortPrivKey)
	return ok && k.c.Params() == k1.c.Params() && bytes.Equal(k.k, k1.k)
}
func (k shortPrivKey) Public() shortPubKey {
	x, y := k.c.ScalarBaseMult(k.k)
	return shortPubKey{k.c, x, y}
}
