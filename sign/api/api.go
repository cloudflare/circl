// Package api contains a register of signature algorithms.
package api

import (
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/eddilithium3"
)

var allSchemes [sign.SchemeCount]sign.Scheme
var allSchemeNames map[string]sign.Scheme

func init() {
	allSchemeNames = make(map[string]sign.Scheme)
	register(eddilithium3.Scheme)
}

func register(s sign.Scheme) {
	allSchemes[s.ID()] = s
	allSchemeNames[s.Name()] = s
}

// SchemeByName returns the scheme with the given name and nil if it is not
// supported.
func SchemeByName(name string) sign.Scheme { return allSchemeNames[name] }

// AllSchemes returns all signature schemes supported.
func AllSchemes() []sign.Scheme { a := allSchemes; return a[:] }
