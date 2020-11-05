// Code generated from pkg.templ.go. DO NOT EDIT.

// sikep751 implements the key encapsulation mechanism SIKEp751.
package sikep751

import (
	"github.com/cloudflare/circl/dh/sidh"
	"github.com/cloudflare/circl/internal/shake"
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

var Scheme kem.Scheme = &scheme{}

var params *sidh.KEM

func (*scheme) Name() string               { return "SIKEp751" }
func (*scheme) PublicKeySize() int         { return params.PublicKeySize() }
func (*scheme) PrivateKeySize() int        { return params.PrivateKeySize() }
func (*scheme) SeedSize() int              { return SeedSize }
func (*scheme) SharedKeySize() int         { return params.SharedSecretSize() }
func (*scheme) CiphertextSize() int        { return params.CiphertextSize() }
func (*scheme) EncapsulationSeedSize() int { return EncapsulationSeedSize }

func (sk *PrivateKey) Scheme() kem.Scheme { return Scheme }
func (pk *PublicKey) Scheme() kem.Scheme  { return Scheme }

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
	sk := sidh.NewPrivateKey(sidh.Fp751, sidh.KeyVariantSike)
	pk := sidh.NewPublicKey(sidh.Fp751, sidh.KeyVariantSike)

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
	h := shake.NewShake256()
	_, _ = h.Write(seed[:])
	pk, sk, err := GenerateKey(&h)

	if err != nil {
		panic(err)
	}

	return pk, sk
}

func (sch *scheme) Encapsulate(pk kem.PublicKey) (ct []byte, ss []byte) {
	var seed [EncapsulationSeedSize]byte
	cryptoRand.Read(seed[:])
	return sch.EncapsulateDeterministically(pk, seed[:])
}

func (sch *scheme) EncapsulateDeterministically(pk kem.PublicKey, seed []byte) (
	ct []byte, ss []byte) {

	if len(seed) != EncapsulationSeedSize {
		panic(kem.ErrSeedSize)
	}

	pub, ok := pk.(*PublicKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}

	ct = make([]byte, sch.CiphertextSize())
	ss = make([]byte, sch.SharedKeySize())

	h := shake.NewShake256()
	_, _ = h.Write(seed[:])
	ctx := sidh.NewSike751(&h)

	if err := ctx.Encapsulate(ct, ss, (*sidh.PublicKey)(pub)); err != nil {
		panic(err)
	}
	return
}

func (sch *scheme) Decapsulate(sk kem.PrivateKey, ct []byte) []byte {
	if len(ct) != sch.CiphertextSize() {
		panic(kem.ErrCiphertextSize)
	}

	priv, ok := sk.(*PrivateKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}

	sikePriv := (*sidh.PrivateKey)(priv)

	sikePub := sidh.NewPublicKey(sidh.Fp751, sidh.KeyVariantSike)
	sikePriv.GeneratePublicKey(sikePub)

	ss := make([]byte, sch.SharedKeySize())

	ctx := sidh.NewSike751(nil)
	if err := ctx.Decapsulate(ss, sikePriv, sikePub, ct); err != nil {
		panic(err)
	}

	return ss
}

func (sch *scheme) UnmarshalBinaryPublicKey(buf []byte) (kem.PublicKey, error) {
	if len(buf) != sch.PublicKeySize() {
		return nil, kem.ErrPubKeySize
	}
	pk := sidh.NewPublicKey(sidh.Fp751, sidh.KeyVariantSike)
	if err := pk.Import(buf); err != nil {
		return nil, err
	}
	return (*PublicKey)(pk), nil
}

func (sch *scheme) UnmarshalBinaryPrivateKey(buf []byte) (kem.PrivateKey, error) {
	if len(buf) != sch.PrivateKeySize() {
		return nil, kem.ErrPrivKeySize
	}
	sk := sidh.NewPrivateKey(sidh.Fp751, sidh.KeyVariantSike)
	if err := sk.Import(buf); err != nil {
		return nil, err
	}
	return (*PrivateKey)(sk), nil
}

func init() {
	params = sidh.NewSike751(nil)
}
