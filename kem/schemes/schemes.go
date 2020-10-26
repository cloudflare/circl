// Package schemes contains a register of KEM schemes.
//
// Schemes Implemented
//
// Based on standard elliptic curves:
//  HpkeDHKemP256HkdfSha256, HpkeDHKemP384HkdfSha384, HpkeDHKemP521HkdfSha512
// Based on standard Diffie-Hellman functions:
//  HpkeDHKemX25519HkdfSha256, HpkeDHKemX448HkdfSha512
// Post-quantum kems:
//  Kyber512, Kyber768, Kyber1024
//  SIKEp434, SIKEp503, SIKEp751
package schemes

import (
	"strings"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/kem/sike/sikep434"
	"github.com/cloudflare/circl/kem/sike/sikep503"
	"github.com/cloudflare/circl/kem/sike/sikep751"
)

var allSchemes = [...]kem.Scheme{
	hpke.DHKemP256HkdfSha256.Scheme(),
	hpke.DHKemP384HkdfSha384.Scheme(),
	hpke.DHKemP521HkdfSha512.Scheme(),
	hpke.DHKemX25519HkdfSha256.Scheme(),
	hpke.DHKemX448HkdfSha512.Scheme(),
	kyber512.Scheme(),
	kyber768.Scheme(),
	kyber1024.Scheme(),
	sikep434.Scheme(),
	sikep503.Scheme(),
	sikep751.Scheme(),
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
