// Package short implements KEM based on a short Weierstrass curves.
package short

import (
	"crypto"
	"crypto/elliptic"
	_ "crypto/sha256" // linking packages
	_ "crypto/sha512" // linking packages

	"github.com/cloudflare/circl/kem"
)

// KemID is used to identify a KEM instance.
type KemID = uint16

const (
	KemP256Sha256 KemID = iota + 0x0010
	KemP384Sha384
	KemP521Sha512
)

var names map[KemID]string

func init() {
	names = make(map[KemID]string)
	names[KemP256Sha256] = "KemP256Sha256"
	names[KemP384Sha384] = "KemP384Sha384"
	names[KemP521Sha512] = "KemP521Sha512"
}

// New returns an authenticaed KEM based on a short Weierstrass curve and HKDF
// as key derivation function. Optionally, a domain-separation tag can be provided.
func New(id KemID, dst []byte) kem.AuthScheme {
	var c elliptic.Curve
	var h crypto.Hash
	switch id {
	case KemP256Sha256:
		c, h = elliptic.P256(), crypto.SHA256
	case KemP384Sha384:
		c, h = elliptic.P384(), crypto.SHA384
	case KemP521Sha512:
		c, h = elliptic.P521(), crypto.SHA512
	default:
		panic("wrong kemID")
	}
	return short{c.Params(), id, h, dst}
}
