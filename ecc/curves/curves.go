// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

// Package curves provides elliptic curves and their object identifiers.
//
// Custom curve operations may be variable time and must not be used with secret
// scalars. See the security documentation in package ecc.
package curves

import (
	"github.com/cloudflare/circl/ecc"
	"github.com/cloudflare/circl/ecc/brainpool"
	"github.com/cloudflare/circl/ecc/nist"
	"github.com/cloudflare/circl/ecc/secg"
	"github.com/cloudflare/circl/ecc/x962"
	"github.com/cloudflare/circl/ecc/x963"
)

// this must be a separate package to avoid circular deps

var allCurves = [...]ecc.Curve{
	brainpool.P160t1(),
	brainpool.P192t1(),
	brainpool.P224t1(),
	brainpool.P256t1(),
	brainpool.P320t1(),
	brainpool.P384t1(),
	brainpool.P512t1(),
	brainpool.P160r1(),
	brainpool.P192r1(),
	brainpool.P224r1(),
	brainpool.P256r1(),
	brainpool.P320r1(),
	brainpool.P384r1(),
	brainpool.P512r1(),
	nist.P192(),
	nist.P224(),
	nist.P256(),
	nist.P384(),
	nist.P521(),
	nist.K163(),
	nist.B163(),
	nist.K233(),
	nist.B233(),
	nist.K283(),
	nist.B283(),
	nist.K409(),
	nist.B409(),
	nist.K571(),
	nist.B571(),
	secg.Secp192r1(),
	secg.Secp224r1(),
	secg.Secp256r1(),
	secg.Secp384r1(),
	secg.Secp521r1(),
	secg.Sect113r1(),
	secg.Sect113r2(),
	secg.Sect131r1(),
	secg.Sect131r2(),
	secg.Sect163k1(),
	secg.Sect163r1(),
	secg.Sect163r2(),
	secg.Sect193r1(),
	secg.Sect193r2(),
	secg.Sect233k1(),
	secg.Sect233r1(),
	secg.Sect239k1(),
	secg.Sect283k1(),
	secg.Sect283r1(),
	secg.Sect409k1(),
	secg.Sect409r1(),
	secg.Sect571k1(),
	secg.Sect571r1(),
	x962.Prime192v1(),
	x962.Prime192v2(),
	x962.Prime192v3(),
	x962.Prime239v1(),
	x962.Prime239v2(),
	x962.Prime239v3(),
	x962.Prime256v1(),
	x962.C2pnb176w1(),
	x962.C2pnb163v1(),
	x962.C2pnb163v2(),
	x962.C2pnb163v3(),
	x962.C2pnb208w1(),
	x962.C2tnb191v3(),
	x962.C2tnb191v2(),
	x962.C2tnb191v1(),
	x962.C2tnb239v3(),
	x962.C2tnb239v2(),
	x962.C2tnb239v1(),
	x962.C2pnb272w1(),
	x962.C2pnb304w1(),
	x962.C2pnb368w1(),
	x962.C2tnb359v1(),
	x962.C2tnb431r1(),
	x963.Ansip224r1(),
	x963.Ansip384r1(),
	x963.Ansip521r1(),
	x963.Ansit163k1(),
	x963.Ansit163r1(),
	x963.Ansit163r2(),
	x963.Ansit193r1(),
	x963.Ansit193r2(),
	x963.Ansit233k1(),
	x963.Ansit233r1(),
	x963.Ansit239k1(),
	x963.Ansit283k1(),
	x963.Ansit283r1(),
	x963.Ansit409k1(),
	x963.Ansit409r1(),
	x963.Ansit571k1(),
	x963.Ansit571r1(),
}

func All() []ecc.Curve { a := allCurves; return a[:] }
