// Code generated from modePkg.templ.go. DO NOT EDIT.

// mode3 implements the MAYO signature scheme MAYO_3
// as submitted to round1 of the NIST PQC competition of Additional Signature Scehemes and described in
//
//	https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-1/spec-files/mayo-spec-web.pdf
//
// This implemented the nibble-sliced version as proposed in
//
//	https://eprint.iacr.org/2023/1683
package mode3

import (
	"crypto"
	"errors"
	"io"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mayo/mode3/internal"
)

const (
	// Size of seed for NewKeyFromSeed
	SeedSize = internal.KeySeedSize

	// Size of a packed PublicKey
	PublicKeySize = internal.PublicKeySize

	// Size of a packed PrivateKey
	PrivateKeySize = internal.PrivateKeySize

	// Size of a signature
	SignatureSize = internal.SignatureSize
)

// PublicKey is the type of Mayo1 public key
type PublicKey internal.PublicKey

// PrivateKey is the type of Mayo1 private key
type PrivateKey internal.PrivateKey

func (sk *PrivateKey) Scheme() sign.Scheme { return sch }
func (pk *PublicKey) Scheme() sign.Scheme  { return sch }

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	pk, sk, err := internal.GenerateKey(rand)
	return (*PublicKey)(pk), (*PrivateKey)(sk), err
}

// NewKeyFromSeed derives a public/private key pair using the given seed.
func NewKeyFromSeed(seed [SeedSize]byte) (*PublicKey, *PrivateKey) {
	pk, sk := internal.NewKeyFromSeed(seed)
	return (*PublicKey)(pk), (*PrivateKey)(sk)
}

// Sign signs the given message using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func Sign(sk *PrivateKey, msg []byte, rand io.Reader) ([]byte, error) {
	return internal.Sign(
		msg,
		(*internal.PrivateKey)(sk).Expand(),
		rand,
	)
}

// Verify checks whether the given signature by pk on msg is valid.
func Verify(pk *PublicKey, msg []byte, signature []byte) bool {
	return internal.Verify(
		(*internal.PublicKey)(pk).Expand(),
		msg,
		signature,
	)
}

// Packs the public key.
func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	var buf [PublicKeySize]byte
	b := [PublicKeySize]byte(*pk)
	copy(buf[:], b[:])
	return buf[:], nil
}

// Packs the private key.
func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	var buf [PrivateKeySize]byte
	b := [PrivateKeySize]byte(*sk)
	copy(buf[:], b[:])
	return buf[:], nil
}

// Unpacks the public key from data.
func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	if len(data) != PublicKeySize {
		return errors.New("packed public key must be of mode3.PublicKeySize bytes")
	}
	self := (*[PublicKeySize]byte)(pk)
	copy(self[:], data[:])
	return nil
}

// Unpacks the private key from data.
func (sk *PrivateKey) UnmarshalBinary(data []byte) error {
	if len(data) != PrivateKeySize {
		return errors.New("packed private key must be of mode3.PrivateKeySize bytes")
	}
	self := (*[PrivateKeySize]byte)(sk)
	copy(self[:], data[:])
	return nil
}

// Sign signs the given message.
//
// opts.HashFunc() must return zero, which can be achieved by passing
// crypto.Hash(0) for opts.  Will only return an error
// if opts.HashFunc() is non-zero.
//
// This function is used to make PrivateKey implement the crypto.Signer
// interface.  The package-level Sign function might be more convenient
// to use.
func (sk *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (
	signature []byte, err error) {
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("mayo: cannot sign hashed message")
	}

	return Sign(sk, msg, rand)
}

// Computes the public key corresponding to this private key.
//
// Returns a *PublicKey.  The type crypto.PublicKey is used to make
// PrivateKey implement the crypto.Signer interface.
func (sk *PrivateKey) Public() crypto.PublicKey {
	return (*internal.PrivateKey)(sk).Public
}

// Equal returns whether the two private keys equal.
func (sk *PrivateKey) Equal(other crypto.PrivateKey) bool {
	castOther, ok := other.(*PrivateKey)
	if !ok {
		return false
	}
	return (*internal.PrivateKey)(sk).Equal((*internal.PrivateKey)(castOther))
}

// Equal returns whether the two public keys equal.
func (pk *PublicKey) Equal(other crypto.PublicKey) bool {
	castOther, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	return (*internal.PublicKey)(pk).Equal((*internal.PublicKey)(castOther))
}
