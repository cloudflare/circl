// Package schemes contains a register of Streamlined NTRU Prime KEM schemes.
//
// # Schemes Implemented
//
// Post-quantum kems:
//
//	SNTRUP653, SNTRUP761, SNTRUP857, SNTRUP953, SNTRUP1013, SNTRUP1277
package schemes

import (
	"strings"

	"github.com/cloudflare/circl/kem/ntruprime/sntrup1013"
	"github.com/cloudflare/circl/kem/ntruprime/sntrup1277"
	"github.com/cloudflare/circl/kem/ntruprime/sntrup653"
	"github.com/cloudflare/circl/kem/ntruprime/sntrup761"
	"github.com/cloudflare/circl/kem/ntruprime/sntrup857"
	"github.com/cloudflare/circl/kem/ntruprime/sntrup953"
	"github.com/cloudflare/circl/pke/ntruprime/kem"
)

var allSchemes = [...]kem.Scheme{
	sntrup653.Scheme(),
	sntrup761.Scheme(),
	sntrup857.Scheme(),
	sntrup953.Scheme(),
	sntrup1013.Scheme(),
	sntrup1277.Scheme(),
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
