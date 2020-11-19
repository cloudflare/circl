// Package kem provides a unified interface for KEM schemes.
//
// A register of schemes is available in the package
//
//  github.com/cloudflare/circl/kem/schemes
package kem

import (
	"encoding"
	"errors"
)

// A KEM public key
type PublicKey interface {
	// Returns the scheme for this public key
	Scheme() Scheme

	encoding.BinaryMarshaler
	Equal(PublicKey) bool
}

// A KEM private key
type PrivateKey interface {
	// Returns the scheme for this private key
	Scheme() Scheme

	encoding.BinaryMarshaler
	Equal(PrivateKey) bool
}

// A Scheme represents a specific instance of a KEM.
type Scheme interface {
	// Name of the scheme
	Name() string

	// GenerateKey creates a new key pair.
	GenerateKey() (PublicKey, PrivateKey, error)

	// Encapsulate generates a shared key ss for the public key and
	// encapsulates it into a ciphertext ct.
	Encapsulate(pk PublicKey) (ct []byte, ss []byte, err error)

	// Returns the shared key encapsulated in ciphertext ct for the
	// private key sk.
	Decapsulate(sk PrivateKey, ct []byte) ([]byte, error)

	// Unmarshals a PublicKey from the provided buffer.
	UnmarshalBinaryPublicKey([]byte) (PublicKey, error)

	// Unmarshals a PrivateKey from the provided buffer.
	UnmarshalBinaryPrivateKey([]byte) (PrivateKey, error)

	// Size of encapsulated keys.
	CiphertextSize() int

	// Size of established shared keys.
	SharedKeySize() int

	// Size of packed private keys.
	PrivateKeySize() int

	// Size of packed public keys.
	PublicKeySize() int

	// Deterministicallly derives a keypair from a seed. If you're unsure,
	// you're better off using GenerateKey().
	//
	// Panics if seed is not of length SeedSize().
	DeriveKey(seed []byte) (PublicKey, PrivateKey)

	// Size of seed used in DeriveKey
	SeedSize() int

	// EncapsulateDeterministically generates a shared key ss for the public
	// key deterministically from the given seed and encapsulates it into
	// a ciphertext ct. If unsure, you're better off using Encapsulate().
	EncapsulateDeterministically(pk PublicKey, seed []byte) (
		ct, ss []byte, err error)

	// Size of seed used in EncapsulateDeterministically().
	EncapsulationSeedSize() int
}

var (
	// ErrTypeMismatch is the error used if types of, for instance, private
	// and public keys don't match
	ErrTypeMismatch = errors.New("types mismatch")

	// ErrSeedSize is the error used if the provided seed is of the wrong
	// size.
	ErrSeedSize = errors.New("wrong seed size")

	// ErrPubKeySize is the error used if the provided public key is of
	// the wrong size.
	ErrPubKeySize = errors.New("wrong size for public key")

	// ErrCiphertextSize is the error used if the provided ciphertext
	// is of the wrong size.
	ErrCiphertextSize = errors.New("wrong size for ciphertext")

	// ErrPrivKeySize is the error used if the provided private key is of
	// the wrong size.
	ErrPrivKeySize = errors.New("wrong size for private key")

	// ErrPubKey is the error used if the provided public key is invalid.
	ErrPubKey = errors.New("invalid public key")

	// ErrCipherText is the error used if the provided ciphertext is invalid.
	ErrCipherText = errors.New("invalid ciphertext")
)
