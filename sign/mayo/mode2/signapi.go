// Code generated from signapi.templ.go. DO NOT EDIT.

package mode2

import (
	"github.com/cloudflare/circl/sign"
)

var sch sign.Scheme = &scheme{}

// Scheme returns a signature interface.
func Scheme() sign.Scheme { return sch }

type scheme struct{}

func (*scheme) Name() string          { return "MAYO_2" }
func (*scheme) PublicKeySize() int    { return PublicKeySize }
func (*scheme) PrivateKeySize() int   { return PrivateKeySize }
func (*scheme) SignatureSize() int    { return SignatureSize }
func (*scheme) SeedSize() int         { return SeedSize }
func (*scheme) SupportsContext() bool { return false }

func (*scheme) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	sk, pk, err := GenerateKey(nil)
	return sk, pk, err
}

func (*scheme) Sign(
	sk sign.PrivateKey,
	message []byte,
	opts *sign.SignatureOpts,
) []byte {
	priv, ok := sk.(*PrivateKey)
	if !ok {
		panic(sign.ErrTypeMismatch)
	}
	if opts != nil && opts.Context != "" {
		panic(sign.ErrContextNotSupported)
	}
	sig, err := Sign(priv, message, nil)
	if err != nil {
		panic("")
	}
	return sig
}

func (*scheme) Verify(
	pk sign.PublicKey,
	message, signature []byte,
	opts *sign.SignatureOpts,
) bool {
	pub, ok := pk.(*PublicKey)
	if !ok {
		panic(sign.ErrTypeMismatch)
	}
	if opts != nil && opts.Context != "" {
		panic(sign.ErrContextNotSupported)
	}
	return Verify(pub, message, signature)
}

func (*scheme) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	if len(seed) != SeedSize {
		panic(sign.ErrSeedSize)
	}
	var tmp [SeedSize]byte
	copy(tmp[:], seed)
	return NewKeyFromSeed(&tmp)
}

func (*scheme) UnmarshalBinaryPublicKey(buf []byte) (sign.PublicKey, error) {
	if len(buf) != PublicKeySize {
		return nil, sign.ErrPubKeySize
	}
	var ret PublicKey
	err := ret.UnmarshalBinary(buf)
	return &ret, err
}

func (*scheme) UnmarshalBinaryPrivateKey(buf []byte) (sign.PrivateKey, error) {
	if len(buf) != PrivateKeySize {
		return nil, sign.ErrPrivKeySize
	}
	var ret PrivateKey
	err := ret.UnmarshalBinary(buf)
	return &ret, err
}
