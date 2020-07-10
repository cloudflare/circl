// Package eddilithium3 implements the hybrid signature scheme Ed25519-Dilithium3.
package eddilithium3

import (
	"crypto"
	cryptoRand "crypto/rand"
	"errors"
	"io"

	"github.com/cloudflare/circl/internal/shake"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/ed25519"
)

const (
	// SeedSize is the length of the seed for NewKeyFromSeed
	SeedSize = mode3.SeedSize // = ed25519.SeedSize = 32

	// PublicKeySize is the length in bytes of the packed public key.
	PublicKeySize = mode3.PublicKeySize + ed25519.PublicKeySize

	// PrivateKeySize is the length in bytes of the packed public key.
	PrivateKeySize = mode3.PrivateKeySize + ed25519.PrivateKeySize

	// SignatureSize is the length in bytes of the signatures.
	SignatureSize = mode3.SignatureSize + ed25519.SignatureSize
)

// PublicKey is the type of an EdDilithium3 public key.
type PublicKey struct {
	e ed25519.PublicKey
	d mode3.PublicKey
}

// PrivateKey is the type of an EdDilithium3 private key.
type PrivateKey struct {
	e ed25519.KeyPair
	d mode3.PrivateKey
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	var seed [SeedSize]byte
	if rand == nil {
		rand = cryptoRand.Reader
	}
	_, err := io.ReadFull(rand, seed[:])
	if err != nil {
		return nil, nil, err
	}

	pk, sk := NewKeyFromSeed(&seed)
	return pk, sk, nil
}

// NewKeyFromSeed derives a public/private key pair using the given seed.
func NewKeyFromSeed(seed *[SeedSize]byte) (*PublicKey, *PrivateKey) {
	var seed1 [32]byte
	var seed2 [32]byte

	// Internally, Ed25519 and Dilithium hash the seeds they are passed again
	// with different hash functions, so it would be safe to use exactly the
	// same seed for Ed25519 and Dilithium here.  However, in general, when
	// combining any two signature schemes it might not be the case that this
	// is safe.  Setting a bad example here isn't worth the tiny gain in
	// performance.

	h := shake.NewShake256()
	_, _ = h.Write(seed[:])
	_, _ = h.Read(seed1[:])
	_, _ = h.Read(seed2[:])
	dpk, dsk := mode3.NewKeyFromSeed(&seed1)
	epair := ed25519.NewKeyFromSeed(seed2[:])

	return &PublicKey{epair.GetPublic(), *dpk}, &PrivateKey{*epair, *dsk}
}

// SignTo signs the given message and writes the signature into signature.
// It will panic if signature is not of length at least SignatureSize.
func SignTo(sk *PrivateKey, msg []byte, signature []byte) {
	mode3.SignTo(
		&sk.d,
		msg,
		signature[:mode3.SignatureSize],
	)
	esig, _ := sk.e.SignPure(
		msg,
	)
	copy(signature[mode3.SignatureSize:], esig[:])
}

// Verify checks whether the given signature by pk on msg is valid.
func Verify(pk *PublicKey, msg []byte, signature []byte) bool {
	if !mode3.Verify(
		&pk.d,
		msg,
		signature[:mode3.SignatureSize],
	) {
		return false
	}
	if !ed25519.Verify(
		pk.e,
		msg,
		signature[mode3.SignatureSize:],
		crypto.Hash(0),
	) {
		return false
	}
	return true
}

// Unpack unpacks pk to the public key encoded in buf.
func (pk *PublicKey) Unpack(buf *[PublicKeySize]byte) {
	var tmp [mode3.PublicKeySize]byte
	copy(tmp[:], buf[:mode3.PublicKeySize])
	pk.d.Unpack(&tmp)
	pk.e = make([]byte, ed25519.PublicKeySize)
	copy(pk.e, buf[mode3.PublicKeySize:])
}

// Unpack sets sk to the private key encoded in buf.
func (sk *PrivateKey) Unpack(buf *[PrivateKeySize]byte) {
	var tmp [mode3.PrivateKeySize]byte
	copy(tmp[:], buf[:mode3.PrivateKeySize])
	sk.d.Unpack(&tmp)
	sk.e = *ed25519.NewKeyFromSeed(buf[mode3.PrivateKeySize:])
}

// Pack packs the public key into buf.
func (pk *PublicKey) Pack(buf *[PublicKeySize]byte) {
	var tmp [mode3.PublicKeySize]byte
	pk.d.Pack(&tmp)
	copy(buf[:mode3.PublicKeySize], tmp[:])
	copy(buf[mode3.PublicKeySize:], pk.e)
}

// Pack packs the private key into buf.
func (sk *PrivateKey) Pack(buf *[PrivateKeySize]byte) {
	var tmp [mode3.PrivateKeySize]byte
	sk.d.Pack(&tmp)
	copy(buf[:mode3.PrivateKeySize], tmp[:])
	copy(buf[mode3.PrivateKeySize:], sk.e.Seed())
}

// Bytes packs the public key.
func (pk *PublicKey) Bytes() []byte {
	return append(pk.d.Bytes(), pk.e...)
}

// Bytes packs the private key.
func (sk *PrivateKey) Bytes() []byte {
	return append(sk.d.Bytes(), sk.e.Seed()...)
}

// MarshalBinary packs the public key.
func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	return pk.Bytes(), nil
}

// MarshalBinary packs the private key.
func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	return sk.Bytes(), nil
}

// UnmarshalBinary the public key from data.
func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	if len(data) != PublicKeySize {
		return errors.New("packed public key must be of eddilithium3.PublicKeySize bytes")
	}
	var buf [PublicKeySize]byte
	copy(buf[:], data)
	pk.Unpack(&buf)
	return nil
}

// UnmarshalBinary unpacks the private key from data.
func (sk *PrivateKey) UnmarshalBinary(data []byte) error {
	if len(data) != PrivateKeySize {
		return errors.New("packed private key must be of eddilithium3.PrivateKeySize bytes")
	}
	var buf [PrivateKeySize]byte
	copy(buf[:], data)
	sk.Unpack(&buf)
	return nil
}

// Sign signs the given message.
//
// opts.HashFunc() must return zero, which can be achieved by passing
// crypto.Hash(0) for opts.  rand is ignored.  Will only return an error
// if opts.HashFunc() is non-zero.
//
// This function is used to make PrivateKey implement the crypto.Signer
// interface.  The package-level SignTo function might be more convenient
// to use.
func (sk *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (
	signature []byte, err error) {
	var sig [SignatureSize]byte

	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("eddilithium3: cannot sign hashed message")
	}

	SignTo(sk, msg, sig[:])
	return sig[:], nil
}

// Public computes the public key corresponding to this private key.
//
// Returns a *PublicKey.  The type crypto.PublicKey is used to make
// PrivateKey implement the crypto.Signer interface.
func (sk *PrivateKey) Public() crypto.PublicKey {
	return &PublicKey{
		sk.e.GetPublic(),
		*sk.d.Public().(*mode3.PublicKey),
	}
}
