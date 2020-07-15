package sign

import (
	"github.com/cloudflare/circl/sign/eddilithium3"

	cryptoRand "crypto/rand"
	"encoding/asn1"
	"errors"
)

type edDilithium3Scheme struct{}

var EdDilithium3 Scheme = &edDilithium3Scheme{}

func (s *edDilithium3Scheme) GenerateKey() (PublicKey, PrivateKey, error) {
	pk, sk, err := eddilithium3.GenerateKey(cryptoRand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return wrapPublicKey(pk, EdDilithium3), wrapPrivateKey(sk, EdDilithium3), nil
}

func (s *edDilithium3Scheme) Sign(sk PrivateKey, message []byte,
	opts *SignatureOpts) []byte {
	sig := make([]byte, eddilithium3.SignatureSize)
	if opts != nil && opts.Context != "" {
		panic("Does not support context")
	}
	eddilithium3.SignTo(
		sk.(*wrappedPrivateKey).wrappee.(*eddilithium3.PrivateKey),
		message,
		sig,
	)
	return sig
}

func (s *edDilithium3Scheme) Verify(pk PublicKey, message, signature []byte,
	opts *SignatureOpts) bool {
	if opts != nil && opts.Context != "" {
		panic("Does not support context")
	}
	return eddilithium3.Verify(
		pk.(*wrappedPublicKey).wrappee.(*eddilithium3.PublicKey),
		message,
		signature,
	)
}

func (s *edDilithium3Scheme) DeriveKey(seed []byte) (PublicKey, PrivateKey) {
	if len(seed) != eddilithium3.SeedSize {
		panic("Wrong seed size")
	}
	var tmp [eddilithium3.SeedSize]byte
	copy(tmp[:], seed)
	pk, sk := eddilithium3.NewKeyFromSeed(&tmp)
	return wrapPublicKey(pk, EdDilithium3), wrapPrivateKey(sk, EdDilithium3)
}

func (s *edDilithium3Scheme) UnmarshalBinaryPublicKey(buf []byte) (
	PublicKey, error) {
	if len(buf) != eddilithium3.PublicKeySize {
		return nil, errors.New("wrong size for public key")
	}
	var tmp [eddilithium3.PublicKeySize]byte
	var ret eddilithium3.PublicKey
	copy(tmp[:], buf)
	ret.Unpack(&tmp)
	return wrapPublicKey(&ret, EdDilithium3), nil
}

func (s *edDilithium3Scheme) UnmarshalBinaryPrivateKey(buf []byte) (PrivateKey, error) {
	if len(buf) != eddilithium3.PrivateKeySize {
		return nil, errors.New("wrong size for private key")
	}
	var tmp [eddilithium3.PrivateKeySize]byte
	var ret eddilithium3.PrivateKey
	copy(tmp[:], buf)
	ret.Unpack(&tmp)
	return wrapPrivateKey(&ret, EdDilithium3), nil
}

func (s *edDilithium3Scheme) PublicKeySize() uint {
	return eddilithium3.PublicKeySize
}

func (s *edDilithium3Scheme) PrivateKeySize() uint {
	return eddilithium3.PrivateKeySize
}

func (s *edDilithium3Scheme) Name() string {
	return "Ed25519-Dilithium3"
}

func (s *edDilithium3Scheme) SignatureSize() uint {
	return eddilithium3.SignatureSize
}

func (s *edDilithium3Scheme) SeedSize() uint {
	return eddilithium3.SeedSize
}

func (s *edDilithium3Scheme) Oid() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 45, 9}
}

func (s *edDilithium3Scheme) TLSIdentifier() uint {
	return 0xfe61 // temp
}
