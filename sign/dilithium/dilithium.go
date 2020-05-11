//go:generate go run gen.go

// dilithium implements the CRYSTALS-Dilithium signature schemes
// as submitted to round2 of the NIST PQC competition and described in
//
// https://pq-crystals.org/dilithium/data/dilithium-specification-round2.pdf
//
// Each of the eight different modes of Dilithium is implemented by a
// subpackge.  For instance, Dilithium III can be found in
//
//  github.com/cloudflare/circl/sign/dilithium/mode3
//
// If your choice for mode is fixed compile-time, use the subpackages.
// This package provides a convenient wrapper around all of the subpackages
// so one can be chosen at runtime.
package dilithium

import (
	"crypto"
	"io"
)

// PublicKey is a Dilithium public key.
//
// The structure contains values precomputed during unpacking/key generation
// and is therefore signficantly larger than a packed public key.
type PublicKey interface {
	// Packs public key
	Bytes() []byte
}

// PrivateKey is a Dilithium public key.
//
// The structure contains values precomputed during unpacking/key generation
// and is therefore signficantly larger than a packed private key.
type PrivateKey interface {
	// Packs private key
	Bytes() []byte

	crypto.Signer
}

// Mode is a certain configuration of the Dilithium signature scheme.
type Mode interface {
	// GenerateKey generates a public/private key pair using entropy from rand.
	// If rand is nil, crypto/rand.Reader will be used.
	GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error)

	// NewKeyFromSeed derives a public/private key pair using the given seed.
	// Panics if len(seed) != SeedSize()
	NewKeyFromSeed(seed []byte) (PublicKey, PrivateKey)

	// NewKeyFromExpandedSeed derives a public/private key pair using the
	// given expanded seed.
	//
	// Use NewKeyFromSeed instead of this function.  This function is only exposed
	// to generate the NIST KAT test vectors.
	NewKeyFromExpandedSeed(seed *[96]byte) (PublicKey, PrivateKey)

	// Sign signs the given message and returns the signature.
	// It will panic if sk has not been generated for this mode.
	Sign(sk PrivateKey, msg []byte) []byte

	// Verify checks whether the given signature by pk on msg is valid.
	// It will panic if pk is of the wrong mode.
	Verify(pk PublicKey, msg []byte, signature []byte) bool

	// Unpacks a public key.  Panics if the buffer is not of PublicKeySize()
	// length.  Precomputes values to speed up subsequent calls to Verify.
	PublicKeyFromBytes([]byte) PublicKey

	// Unpacks a private key.  Panics if the buffer is not
	// of PrivateKeySize() length.  Precomputes values to speed up subsequent
	// calls to Sign(To).
	PrivateKeyFromBytes([]byte) PrivateKey

	// SeedSize returns the size of the seed for NewKeyFromSeed
	SeedSize() int

	// PublicKeySize returns the size of a packed PublicKey
	PublicKeySize() int

	// PrivateKeySize returns the size  of a packed PrivateKey
	PrivateKeySize() int

	// SignatureSize returns the size  of a signature
	SignatureSize() int

	// Name returns the name of this mode
	Name() string
}

var modes = make(map[string]Mode)

// ModeNames returns the list of supported modes.
func ModeNames() []string {
	names := []string{}
	for name := range modes {
		names = append(names, name)
	}
	return names
}

// ModeByName returns the mode with the given name or nil when not supported.
func ModeByName(name string) Mode {
	return modes[name]
}
