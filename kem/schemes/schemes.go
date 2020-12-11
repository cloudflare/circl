// Package schemes contains a register of KEM schemes.
//
// Schemes Implemented
//
// Based on standard elliptic curves:
//  HPKE_KEM_P256_HKDF_SHA256, HPKE_KEM_P384_HKDF_SHA384, HPKE_KEM_P521_HKDF_SHA512
// Based on standard Diffie-Hellman functions:
//  HPKE_KEM_X25519_HKDF_SHA256, HPKE_KEM_X448_HKDF_SHA512
// Post-quantum kems:
//  Kyber512, Kyber768, Kyber1024
//  SIKEp434, SIKEp503, SIKEp751
package schemes

import (
	"strings"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/hybrid"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/kem/sike/sikep434"
	"github.com/cloudflare/circl/kem/sike/sikep503"
	"github.com/cloudflare/circl/kem/sike/sikep751"
)

var allSchemes = [...]kem.Scheme{
	hpke.KEM_P256_HKDF_SHA256.Scheme(),
	hpke.KEM_P384_HKDF_SHA384.Scheme(),
	hpke.KEM_P521_HKDF_SHA512.Scheme(),
	hpke.KEM_X25519_HKDF_SHA256.Scheme(),
	hpke.KEM_X448_HKDF_SHA512.Scheme(),
	kyber512.Scheme(),
	kyber768.Scheme(),
	kyber1024.Scheme(),
	sikep434.Scheme(),
	sikep503.Scheme(),
	sikep751.Scheme(),
	hybrid.KyberSike(), // XXX temporary for testing
}

var allSchemeNames map[string]kem.Scheme

func init() {
	allSchemeNames = make(map[string]kem.Scheme)
	for _, scheme := range allSchemes {
		allSchemeNames[strings.ToLower(scheme.Name())] = scheme
	}
}

// ByName returns the scheme with the given name and nil if it is not
// supported.
//
// Names are case insensitive.
func ByName(name string) kem.Scheme {
	return allSchemeNames[strings.ToLower(name)]
}

// All returns all KEM schemes supported.
func All() []kem.Scheme { a := allSchemes; return a[:] }
