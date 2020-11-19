// Package short implements a KEM based on short Weierstrass curves.
package short

import (
	"crypto"
	"crypto/elliptic"

	"github.com/cloudflare/circl/ecc/p384"
	"github.com/cloudflare/circl/kem"
)

// KemP256Sha256 is
var KemP256Sha256 kem.Scheme = short{elliptic.P256(), 0x10, "KemP256HkdfSha256", crypto.SHA256}

// KemP384Sha384 is
var KemP384Sha384 kem.Scheme = short{p384.P384(), 0x11, "KemP384HkdfSha384", crypto.SHA384}

// KemP521Sha512 is
var KemP521Sha512 kem.Scheme = short{elliptic.P521(), 0x12, "KemP521HkdfSha512", crypto.SHA512}
