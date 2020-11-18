// Package short implements a KEM based on short Weierstrass curves.
package short

import (
	"crypto"
	"crypto/elliptic"
	_ "crypto/sha256" // linking sha256 package.
	_ "crypto/sha512" // linking sha512 package.

	"github.com/cloudflare/circl/ecc/p384"
	"github.com/cloudflare/circl/kem"
)

// KemID is used to identify a KEM instance.
type KemID = uint16

const (
	KemP256Sha256 KemID = 0x0010
	KemP384Sha384 KemID = 0x0011
	KemP521Sha512 KemID = 0x0012
)

var names map[KemID]string

func init() {
	names = make(map[KemID]string)
	names[KemP256Sha256] = "KemP256Sha256"
	names[KemP384Sha384] = "KemP384Sha384"
	names[KemP521Sha512] = "KemP521Sha512"
}

// New returns an authenticaed KEM based on a short Weierstrass curve and HKDF
// as the key derivation function.
func New(id KemID) kem.AuthScheme {
	var c elliptic.Curve
	var h crypto.Hash
	switch id {
	case KemP256Sha256:
		c, h = elliptic.P256(), crypto.SHA256
	case KemP384Sha384:
		c, h = p384.P384(), crypto.SHA384
	case KemP521Sha512:
		c, h = elliptic.P521(), crypto.SHA512
	default:
		panic("invalid kemid")
	}
	return short{c.Params(), id, h}
}
