// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

// Package secg provides elliptic curves and their object identifiers.
//
// Custom curve operations may be variable time and must not be used with secret
// scalars. See the security documentation in package ecc.
package secg

import (
	"github.com/cloudflare/circl/ecc"
)

func Secp192r1() ecc.Curve {
	initonce.Do(initAll)
	return secp192r1
}

func Secp224r1() ecc.Curve {
	initonce.Do(initAll)
	return secp224r1
}

func Secp256r1() ecc.Curve {
	initonce.Do(initAll)
	return secp256r1
}

func Secp384r1() ecc.Curve {
	initonce.Do(initAll)
	return secp384r1
}

func Secp521r1() ecc.Curve {
	initonce.Do(initAll)
	return secp521r1
}

// binary parameters

func Sect113r1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return sect113r1
}

func Sect113r2() ecc.BinaryCurve {
	initonce.Do(initAll)
	return sect113r2
}

func Sect131r1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return sect131r1
}

func Sect131r2() ecc.BinaryCurve {
	initonce.Do(initAll)
	return sect131r2
}

func Sect163k1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return sect163k1
}

func Sect163r1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return sect163r1
}

func Sect163r2() ecc.BinaryCurve {
	initonce.Do(initAll)
	return sect163r2
}

func Sect193r1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return sect193r1
}

func Sect193r2() ecc.BinaryCurve {
	initonce.Do(initAll)
	return sect193r2
}

func Sect233k1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return sect233k1
}

func Sect233r1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return sect233r1
}

func Sect239k1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return sect239k1
}

func Sect283k1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return sect283k1
}

func Sect283r1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return sect283r1
}

func Sect409k1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return sect409k1
}

func Sect409r1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return sect409r1
}

func Sect571k1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return sect571k1
}

func Sect571r1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return sect571r1
}
