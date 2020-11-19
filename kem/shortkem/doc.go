// Package shortkem implements a KEM based on short Weierstrass curves.
package shortkem

import (
	"crypto"
	"crypto/elliptic"

	"github.com/cloudflare/circl/ecc/p384"
	"github.com/cloudflare/circl/kem"
)

// P256HkdfSha256 is a KEM using P256 curve with HKDF based on SHA-256.
func P256HkdfSha256() kem.AuthScheme {
	return short{elliptic.P256(), 0x10, "KemP256HkdfSha256", crypto.SHA256}
}

// P384HkdfSha384 is a KEM using P384 curve with HKDF based on SHA-384.
func P384HkdfSha384() kem.AuthScheme {
	return short{p384.P384(), 0x11, "KemP384HkdfSha384", crypto.SHA384}
}

// P521HkdfSha512 is a KEM using P521 curve with HKDF based on SHA-512.
func P521HkdfSha512() kem.AuthScheme {
	return short{elliptic.P521(), 0x12, "KemP521HkdfSha512", crypto.SHA512}
}
