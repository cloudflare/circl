// Package schemes contains a register of KEM schemes.
package schemes

import (
	"strings"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/kem/shortkem"
	"github.com/cloudflare/circl/kem/sike/sikep434"
	"github.com/cloudflare/circl/kem/sike/sikep503"
	"github.com/cloudflare/circl/kem/sike/sikep751"
	"github.com/cloudflare/circl/kem/xkem"
)

var allSchemes = [...]kem.Scheme{
	shortkem.P256HkdfSha256(),
	shortkem.P384HkdfSha384(),
	shortkem.P521HkdfSha512(),
	xkem.X25519HkdfSha256(),
	xkem.X448HkdfSha512(),
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
