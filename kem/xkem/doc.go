// Package xkem implements KEM based on X25519 and X448.
package xkem

import (
	"crypto"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/kem"
)

// X25519HkdfSha256 is a KEM using X25519 Diffie-Hellman function with HKDF based on SHA-256.
func X25519HkdfSha256() kem.AuthScheme {
	return xkem{x25519.Size, 0x20, "KemX25519HkdfSha256", crypto.SHA256}
}

// X448HkdfSha512 is a KEM using X448 Diffie-Hellman function with HKDF based on SHA-512.
func X448HkdfSha512() kem.AuthScheme {
	return xkem{x448.Size, 0x21, "KemX448HkdfSha512", crypto.SHA512}
}
