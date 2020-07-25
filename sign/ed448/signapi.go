package ed448

import (
	"crypto/rand"
	"encoding/asn1"

	"github.com/cloudflare/circl/sign"
)

// Scheme is
const Scheme = scheme(sign.Ed448)

type scheme sign.SchemeID

func (scheme) ID() sign.SchemeID    { return sign.SchemeID(Scheme) }
func (scheme) Name() string         { return "Ed448" }
func (scheme) PublicKeySize() uint  { return PublicKeySize }
func (scheme) PrivateKeySize() uint { return PrivateKeySize }
func (scheme) SignatureSize() uint  { return SignatureSize }
func (scheme) SeedSize() uint       { return SeedSize }
func (scheme) TLSIdentifier() uint  { return 0xfe61 /* TODO */ }
func (scheme) Oid() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 17, 10 /* TODO */}
}

func (scheme) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	return GenerateKey(rand.Reader)
}

func (scheme) Sign(
	sk sign.PrivateKey,
	message []byte,
	opts *sign.SignatureOpts) []byte {
	priv, ok := sk.(PrivateKey)
	if !ok {
		panic(sign.ErrType)
	}
	return Sign(priv, message, opts.Context)
}

func (scheme) Verify(
	pk sign.PublicKey,
	message, signature []byte,
	opts *sign.SignatureOpts) bool {
	pub, ok := pk.(PublicKey)
	if !ok {
		panic(sign.ErrType)
	}
	return Verify(pub, message, signature, opts.Context)
}

func (scheme) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	privateKey := NewKeyFromSeed(seed)
	publicKey := make(PublicKey, PublicKeySize)
	copy(publicKey, privateKey[SeedSize:])
	return publicKey, privateKey
}

func (scheme) UnmarshalBinaryPublicKey(buf []byte) (sign.PublicKey, error) {
	if len(buf) < PublicKeySize {
		return nil, sign.ErrPubKeySize
	}
	pub := make(PublicKey, PublicKeySize)
	copy(pub, buf[:PublicKeySize])
	return pub, nil
}

func (scheme) UnmarshalBinaryPrivateKey(buf []byte) (sign.PrivateKey, error) {
	if len(buf) < PrivateKeySize {
		return nil, sign.ErrPrivKeySize
	}
	priv := make(PrivateKey, PrivateKeySize)
	copy(priv, buf[:PrivateKeySize])
	return priv, nil
}
