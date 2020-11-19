// Code generated from pkg.templ.go. DO NOT EDIT.

// sikep434 implements the key encapsulation mechanism SIKEp434.
package sikep434

import (
	"github.com/cloudflare/circl/dh/sidh"
	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/kem"

	"bytes"
	cryptoRand "crypto/rand"
	"crypto/subtle"
	"io"
)

type PrivateKey sidh.PrivateKey
type PublicKey sidh.PublicKey

const (
	SeedSize              = 32
	EncapsulationSeedSize = 32
)

type scheme struct{}

var sch kem.Scheme = &scheme{}

// Scheme returns a KEM interface.
func Scheme() kem.Scheme { return sch }

var params *sidh.KEM

func (*scheme) Name() string               { return "SIKEp434" }
func (*scheme) PublicKeySize() int         { return params.PublicKeySize() }
func (*scheme) PrivateKeySize() int        { return params.PrivateKeySize() }
func (*scheme) SeedSize() int              { return SeedSize }
func (*scheme) SharedKeySize() int         { return params.SharedSecretSize() }
func (*scheme) CiphertextSize() int        { return params.CiphertextSize() }
func (*scheme) EncapsulationSeedSize() int { return EncapsulationSeedSize }

func (sk *PrivateKey) Scheme() kem.Scheme { return sch }
func (pk *PublicKey) Scheme() kem.Scheme  { return sch }

func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	csk := (*sidh.PrivateKey)(sk)
	ret := make([]byte, csk.Size())
	csk.Export(ret)
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

func GenerateKey(rand io.Reader) (kem.PublicKey, kem.PrivateKey, error) {
	sk := sidh.NewPrivateKey(sidh.Fp434, sidh.KeyVariantSike)
	pk := sidh.NewPublicKey(sidh.Fp434, sidh.KeyVariantSike)

	if err := sk.Generate(rand); err != nil {
		return nil, nil, err
	}

	sk.GeneratePublicKey(pk)

	return (*PublicKey)(pk), (*PrivateKey)(sk), nil
}

func (*scheme) GenerateKey() (kem.PublicKey, kem.PrivateKey, error) {
	return GenerateKey(cryptoRand.Reader)
}

func (*scheme) DeriveKey(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	if len(seed) != SeedSize {
		panic(kem.ErrSeedSize)
	}
	h := sha3.NewShake256()
	_, _ = h.Write(seed[:])
	pk, sk, err := GenerateKey(&h)

	if err != nil {
		panic(err)
	}

	return pk, sk
}

func (sch *scheme) Encapsulate(pk kem.PublicKey) (ct []byte, ss []byte, err error) {
	var seed [EncapsulationSeedSize]byte
	cryptoRand.Read(seed[:])
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
	ctx := sidh.NewSike434(&h)

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

	sikePriv := (*sidh.PrivateKey)(priv)

	sikePub := sidh.NewPublicKey(sidh.Fp434, sidh.KeyVariantSike)
	sikePriv.GeneratePublicKey(sikePub)

	ss := make([]byte, sch.SharedKeySize())

	ctx := sidh.NewSike434(nil)
	if err := ctx.Decapsulate(ss, sikePriv, sikePub, ct); err != nil {
		return nil, err
	}

	return ss, nil
}

func (sch *scheme) UnmarshalBinaryPublicKey(buf []byte) (kem.PublicKey, error) {
	if len(buf) != sch.PublicKeySize() {
		return nil, kem.ErrPubKeySize
	}
	pk := sidh.NewPublicKey(sidh.Fp434, sidh.KeyVariantSike)
	if err := pk.Import(buf); err != nil {
		return nil, err
	}
	return (*PublicKey)(pk), nil
}

func (sch *scheme) UnmarshalBinaryPrivateKey(buf []byte) (kem.PrivateKey, error) {
	if len(buf) != sch.PrivateKeySize() {
		return nil, kem.ErrPrivKeySize
	}
	sk := sidh.NewPrivateKey(sidh.Fp434, sidh.KeyVariantSike)
	if err := sk.Import(buf); err != nil {
		return nil, err
	}
	return (*PrivateKey)(sk), nil
}

func init() {
	params = sidh.NewSike434(nil)
}
