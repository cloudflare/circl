// Package sign provides unified interfaces for signature schemes.
package sign

import (
	"crypto"
	"encoding"
	"errors"
)

// SchemeID is an identifier of a signature scheme.
type SchemeID uint8

const (
	Ed25519 SchemeID = iota
	Ed448
	// EdDilithium3 is
	EdDilithium3
	// EdDilithium4 is
	EdDilithium4
	// SchemeCount is the number of supported signature algorithms.
	SchemeCount
)

type SignatureOpts struct {
	crypto.Hash
	// If non-empty, includes the given context in the signature if supported
	// and will cause an error during signing otherwise.
	Context string
}

// A public key is used to verify a signature set by the corresponding private
// key.
type PublicKey interface {
	// Returns the signature scheme for this public key.
	Scheme() Scheme
	Equal(crypto.PublicKey) bool
	encoding.BinaryMarshaler
	crypto.PublicKey
}

// A private key allows one to create signatures.
type PrivateKey interface {
	// Returns the signature scheme for this private key.
	Scheme() Scheme

	Equal(crypto.PrivateKey) bool
	// For compatibility with Go standard library
	crypto.Signer
	crypto.PrivateKey
	encoding.BinaryMarshaler
}

// A Scheme represents a specific instance of a signature scheme.
type Scheme interface {
	// Name of the scheme
	Name() string

	// ID of the scheme
	ID() SchemeID

	// GenerateKey creates a new key-pair.
	GenerateKey() (PublicKey, PrivateKey, error)

	// Creates a signature using the PrivateKey on the given message and
	// returns the signature. opts are additional options which can be nil.
	Sign(sk PrivateKey, message []byte, opts *SignatureOpts) []byte

	// Checks whether the given signature is a valid signature set by
	// the private key corresponding to the given public key on the
	// given message. opts are additional options which can be nil.
	Verify(pk PublicKey, message []byte, signature []byte, opts *SignatureOpts) bool

	// Deterministically derives a keypair from a seed.  If you're unsure,
	// you're better off using GenerateKey().
	//
	// Panics if seed is not of length SeedSize().
	DeriveKey(seed []byte) (PublicKey, PrivateKey)

	// Unmarshals a PublicKey from the provided buffer.
	UnmarshalBinaryPublicKey([]byte) (PublicKey, error)

	// Unmarshals a PublicKey from the provided buffer.
	UnmarshalBinaryPrivateKey([]byte) (PrivateKey, error)

	// Size of binary marshalled public keys
	PublicKeySize() uint

	// Size of binary marshalled public keys
	PrivateKeySize() uint

	// Size of signatures
	SignatureSize() uint

	// Size of seeds
	SeedSize() uint
}

var (
	// ErrType is
	ErrType = errors.New("types mismatch")
	// ErrSeedSize is
	ErrSeedSize = errors.New("wrong seed size")
	// ErrPubKeySize is
	ErrPubKeySize = errors.New("wrong size for public key")
	// ErrPrivKeySize is
	ErrPrivKeySize = errors.New("wrong size for private key")
)
