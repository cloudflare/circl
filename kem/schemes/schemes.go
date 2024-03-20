// Package schemes contains a register of KEM schemes.
//
// # Schemes Implemented
//
// Based on standard elliptic curves:
//
//	HPKE_KEM_P256_HKDF_SHA256, HPKE_KEM_P384_HKDF_SHA384, HPKE_KEM_P521_HKDF_SHA512
//
// Based on standard Diffie-Hellman functions:
//
//	HPKE_KEM_X25519_HKDF_SHA256, HPKE_KEM_X448_HKDF_SHA512
//
// Post-quantum kems:
//
//	FrodoKEM-640-SHAKE
//	Kyber512, Kyber768, Kyber1024
//	Kyber512, Kyber768, Kyber1024
//  NTRULPR653, NTRULPR761, NTRULPR857, NTRULPR953, NTRULPR1013, NTRULPR1277
//	SNTRUP653, SNTRUP761, SNTRUP857, SNTRUP953, SNTRUP1013, SNTRUP1277

package schemes

import (
	"strings"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/frodo/frodo640shake"
	"github.com/cloudflare/circl/kem/hybrid"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/kem/ntruprime/ntrulpr1013"
	"github.com/cloudflare/circl/kem/ntruprime/ntrulpr1277"
	"github.com/cloudflare/circl/kem/ntruprime/ntrulpr653"
	"github.com/cloudflare/circl/kem/ntruprime/ntrulpr761"
	"github.com/cloudflare/circl/kem/ntruprime/ntrulpr857"
	"github.com/cloudflare/circl/kem/ntruprime/ntrulpr953"
	"github.com/cloudflare/circl/kem/ntruprime/sntrup1013"
	"github.com/cloudflare/circl/kem/ntruprime/sntrup1277"
	"github.com/cloudflare/circl/kem/ntruprime/sntrup653"
	"github.com/cloudflare/circl/kem/ntruprime/sntrup761"
	"github.com/cloudflare/circl/kem/ntruprime/sntrup857"
	"github.com/cloudflare/circl/kem/ntruprime/sntrup953"
)

var allSchemes = [...]kem.Scheme{
	hpke.KEM_P256_HKDF_SHA256.Scheme(),
	hpke.KEM_P384_HKDF_SHA384.Scheme(),
	hpke.KEM_P521_HKDF_SHA512.Scheme(),
	hpke.KEM_X25519_HKDF_SHA256.Scheme(),
	hpke.KEM_X448_HKDF_SHA512.Scheme(),
	frodo640shake.Scheme(),
	kyber512.Scheme(),
	kyber768.Scheme(),
	kyber1024.Scheme(),
	hybrid.Kyber512X25519(),
	hybrid.Kyber768X25519(),
	hybrid.Kyber768X448(),
	hybrid.Kyber1024X448(),
	hybrid.P256Kyber768Draft00(),
	ntrulpr653.Scheme(),
	ntrulpr761.Scheme(),
	ntrulpr857.Scheme(),
	ntrulpr953.Scheme(),
	ntrulpr1013.Scheme(),
	ntrulpr1277.Scheme(),
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
