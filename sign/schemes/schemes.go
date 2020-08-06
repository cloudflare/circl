// Package schemes contains a register of signature algorithms.
package schemes

import (
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/cloudflare/circl/sign/eddilithium3"
	"github.com/cloudflare/circl/sign/eddilithium4"
)

var allSchemes = [...]sign.Scheme{
	ed25519.Scheme,
	ed448.Scheme,
	eddilithium3.Scheme,
	eddilithium4.Scheme,
}

var allSchemeNames map[string]sign.Scheme

func init() {
	allSchemeNames = make(map[string]sign.Scheme)
	for _, scheme := range allSchemes {
		allSchemeNames[scheme.Name()] = scheme
	}
}

// ByName returns the scheme with the given name and nil if it is not
// supported.
func ByName(name string) sign.Scheme { return allSchemeNames[name] }

// All returns all signature schemes supported.
func All() []sign.Scheme { a := allSchemes; return a[:] }
