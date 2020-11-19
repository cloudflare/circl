// Package xkem implements KEM based on X25519 and X448.
package xkem

import (
	"crypto"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/kem"
)

// KemX25519Sha256 is
var KemX25519Sha256 kem.Scheme = xkem{x25519.Size, 0x20, "KemX25519Sha256", crypto.SHA256}

// KemX448Sha512 is
var KemX448Sha512 kem.Scheme = xkem{x448.Size, 0x21, "KemX448Sha512", crypto.SHA512}
