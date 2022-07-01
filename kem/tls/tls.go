// Package tls adds helpers to integrate the KEMs supported in CIRCL into TLS.
package tls

import (
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/schemes"
)

var (
	allSchemesByCurveID map[uint]kem.Scheme
)

func init() {
	allSchemesByCurveID = make(map[uint]kem.Scheme)
	for _, scheme := range schemes.All() {
		if tlsScheme, ok := scheme.(TLSScheme); ok {
			allSchemesByCurveID[tlsScheme.TLSCurveID()] = scheme
		}
	}
}

// Returns scheme with the given TLS CurveID, if any.
func SchemeByCurveID(id uint) kem.Scheme { return allSchemesByCurveID[id] }

// Additional methods when the KEM scheme is supported in TLS.
type TLSScheme interface {
    // Returns TLS CurveID for this KEM.
	TLSCurveID() uint
}

