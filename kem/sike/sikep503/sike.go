// Code generated from pkg.templ.go. DO NOT EDIT.

// Package sikep503 is deprecated, it implements the key encapsulation mechanism SIKEp503.
//
// # DEPRECATION NOTICE
//
// SIDH and SIKE are deprecated as were shown vulnerable to a key recovery
// attack by Castryck-Decru's paper (https://eprint.iacr.org/2022/975). New
// systems should not rely on this package. This package is frozen.
package sikep503

import (
	"bytes"
	cryptoRand "crypto/rand"
	"crypto/subtle"
	"io"

	"github.com/cloudflare/circl/dh/sidh"
	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/kem"
)

// Deprecated: not cryptographically secure.
type PrivateKey struct {
	sk *sidh.PrivateKey
	pk *sidh.PublicKey
}

// Deprecated: not cryptographically secure.
type PublicKey sidh.PublicKey

const (
	SeedSize              = 32
	EncapsulationSeedSize = 32
)

type scheme struct{}

var sch kem.Scheme = &scheme{}

// Scheme returns a KEM interface.
//
// Deprecated: not cryptographically secure.
func Scheme() kem.Scheme { return sch }

var params *sidh.KEM

func (*scheme) Name() string               { return "SIKEp503" }
func (*scheme) PublicKeySize() int         { return params.PublicKeySize() }
func (*scheme) PrivateKeySize() int        { return params.PrivateKeySize() }
func (*scheme) SeedSize() int              { return SeedSize }
func (*scheme) SharedKeySize() int         { return params.SharedSecretSize() }
func (*scheme) CiphertextSize() int        { return params.CiphertextSize() }
func (*scheme) EncapsulationSeedSize() int { return EncapsulationSeedSize }

func (sk *PrivateKey) Scheme() kem.Scheme { return sch }
func (pk *PublicKey) Scheme() kem.Scheme  { return sch }

func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	ret := make([]byte, sk.sk.Size())
	sk.sk.Export(ret)
	return ret, nil
}

func (sk *PrivateKey) Equal(other kem.PrivateKey) bool {
	oth, ok := other.(*PrivateKey)
	if !ok {
		return false
	}
	a, _ := sk.MarshalBinary()
	b, _ := oth.MarshalBinary()
	return subtle.ConstantTimeCompare(a, b) == 1
}

func (sk *PrivateKey) Public() kem.PublicKey {
	if sk.pk == nil {
		sk.pk = sidh.NewPublicKey(sidh.Fp503, sidh.KeyVariantSike)
		sk.sk.GeneratePublicKey(sk.pk)
	}
	return (*PublicKey)(sk.pk)
}

func (pk *PublicKey) Equal(other kem.PublicKey) bool {
	oth, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	a, _ := pk.MarshalBinary()
	b, _ := oth.MarshalBinary()
	return bytes.Equal(a, b)
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	cpk := (*sidh.PublicKey)(pk)
	ret := make([]byte, cpk.Size())
	cpk.Export(ret)
	return ret, nil
}

// Deprecated: not cryptographically secure.
func GenerateKeyPair(rand io.Reader) (kem.PublicKey, kem.PrivateKey, error) {
	sk := sidh.NewPrivateKey(sidh.Fp503, sidh.KeyVariantSike)

	if err := sk.Generate(rand); err != nil {
		return nil, nil, err
	}
	priv := &PrivateKey{sk: sk}

	return priv.Public(), priv, nil
}

func (*scheme) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	return GenerateKeyPair(cryptoRand.Reader)
}

func (*scheme) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	if len(seed) != SeedSize {
		panic(kem.ErrSeedSize)
	}
	h := sha3.NewShake256()
	_, _ = h.Write(seed[:])
	pk, sk, err := GenerateKeyPair(&h)

	if err != nil {
		panic(err)
	}

	return pk, sk
}

func (sch *scheme) Encapsulate(pk kem.PublicKey) (ct []byte, ss []byte, err error) {
	var seed [EncapsulationSeedSize]byte
	if _, err := cryptoRand.Read(seed[:]); err != nil {
		return nil, nil, err
	}
	return sch.EncapsulateDeterministically(pk, seed[:])
}

func (sch *scheme) EncapsulateDeterministically(pk kem.PublicKey, seed []byte) (ct []byte, ss []byte, err error) {
	if len(seed) != EncapsulationSeedSize {
		return nil, nil, kem.ErrSeedSize
	}

	pub, ok := pk.(*PublicKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}

	ct = make([]byte, sch.CiphertextSize())
	ss = make([]byte, sch.SharedKeySize())

	h := sha3.NewShake256()
	_, _ = h.Write(seed[:])
	ctx := sidh.NewSike503(&h)

	if err := ctx.Encapsulate(ct, ss, (*sidh.PublicKey)(pub)); err != nil {
		return nil, nil, err
	}
	return ct, ss, nil
}

func (sch *scheme) Decapsulate(sk kem.PrivateKey, ct []byte) ([]byte, error) {
	if len(ct) != sch.CiphertextSize() {
		return nil, kem.ErrCiphertextSize
	}

	priv, ok := sk.(*PrivateKey)
	if !ok {
		return nil, kem.ErrTypeMismatch
	}

	sikePub := sidh.NewPublicKey(sidh.Fp503, sidh.KeyVariantSike)
	priv.sk.GeneratePublicKey(sikePub)

	ss := make([]byte, sch.SharedKeySize())

	ctx := sidh.NewSike503(nil)
	if err := ctx.Decapsulate(ss, priv.sk, sikePub, ct); err != nil {
		return nil, err
	}

	return ss, nil
}

func (sch *scheme) UnmarshalBinaryPublicKey(buf []byte) (kem.PublicKey, error) {
	if len(buf) != sch.PublicKeySize() {
		return nil, kem.ErrPubKeySize
	}
	pk := sidh.NewPublicKey(sidh.Fp503, sidh.KeyVariantSike)
	if err := pk.Import(buf); err != nil {
		return nil, err
	}
	return (*PublicKey)(pk), nil
}

func (sch *scheme) UnmarshalBinaryPrivateKey(buf []byte) (kem.PrivateKey, error) {
	if len(buf) != sch.PrivateKeySize() {
		return nil, kem.ErrPrivKeySize
	}
	sk := sidh.NewPrivateKey(sidh.Fp503, sidh.KeyVariantSike)
	if err := sk.Import(buf); err != nil {
		return nil, err
	}
	return &PrivateKey{sk: sk}, nil
}

func init() {
	params = sidh.NewSike503(nil)
}
