// Package kem provides a unified interface for Streamlined NTRU Prime KEM schemes.
//
// # A register of Streamlined NTRU Prime schemes is available in the package
//
// github.com/cloudflare/circl/pke/ntruprime/kem/schemes/sntrup
package kem

import (
	"github.com/cloudflare/circl/internal/nist"
	"github.com/cloudflare/circl/kem"
)

// A Scheme represents a specific instance of a NTRU PRIME KEM.
type Scheme interface {
	kem.Scheme

	// DeriveKeyPairFromGen deterministicallly derives a pair of keys from a nist DRBG.
	// Only used for deterministic testing
	DeriveKeyPairFromGen(gen *nist.DRBG) (kem.PublicKey, kem.PrivateKey)
}
