// Package xkem implements KEM based on X25519 and X448.
package xkem

import (
	"crypto"
	_ "crypto/sha256" // linking packages
	_ "crypto/sha512" // linking packages

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/kem"
)

// KemID is used to identify a KEM instance.
type KemID = uint16

const (
	KemX25519Sha256 KemID = 0x0020 + iota
	KemX448Sha512
)

var names map[KemID]string

func init() {
	names = make(map[KemID]string)
	names[KemX25519Sha256] = "KemX25519Sha256"
	names[KemX448Sha512] = "KemX448Sha512"
}

// New returns an authenticaed KEM based on X25519 or X448 and using HKDF
// as key derivation function. Optionally, a domain-separation tag can be provided.
func New(id KemID, dst []byte) kem.AuthScheme {
	var h crypto.Hash
	var s int
	switch id {
	case KemX25519Sha256:
		s, h = x25519.Size, crypto.SHA256
	case KemX448Sha512:
		s, h = x448.Size, crypto.SHA512
	default:
		panic("wrong kemID")
	}
	return xkem{id, s, h, dst}
}
