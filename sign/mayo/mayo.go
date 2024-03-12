//go:generate go run gen.go

// Package mayo implements the MAYO signature scheme
// as submitted to round1 of the NIST PQC competition of Additional Signature Scehemes and described in
//
//	https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-1/spec-files/mayo-spec-web.pdf
//
// This implemented the nibble-sliced version as proposed in
//
//	https://eprint.iacr.org/2023/1683
//
// and the code is written with heavy reference to
//
//	https://github.com/PQCMayo/MAYO-C/tree/nibbling-mayo
package mayo

import (
	"crypto"
	"io"
)

// PublicKey is a MAYO public key.
//
// The structure contains values precomputed during unpacking/key generation
// and is therefore significantly larger than a packed public key.
type PublicKey interface {
	// Packs public key
	Bytes() []byte
}

// PrivateKey is a MAYO public key.
//
// The structure contains values precomputed during unpacking/key generation
// and is therefore significantly larger than a packed private key.
type PrivateKey interface {
	// Packs private key
	Bytes() []byte

	crypto.Signer
}

// Mode is a certain configuration of the MAYO signature scheme.
type Mode interface {
	// GenerateKey generates a public/private key pair using entropy from rand.
	// If rand is nil, crypto/rand.Reader will be used.
	GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error)

	// NewKeyFromSeed derives a public/private key pair using the given seed.
	// Panics if len(seed) != SeedSize()
	NewKeyFromSeed(seed []byte) (PublicKey, PrivateKey)

	// Sign signs the given message using entropy from rand and returns the signature.
	// If rand is nil, crypto/rand.Reader will be used.
	// It will panic if sk has not been generated for this mode.
	Sign(sk PrivateKey, msg []byte, rand io.Reader) ([]byte, error)

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
