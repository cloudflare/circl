// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

// Package x963 provides elliptic curves and their object identifiers.
//
// Custom curve operations may be variable time and must not be used with secret
// scalars. See the security documentation in package ecc.
package x963

import (
	"github.com/cloudflare/circl/ecc"
)

func Ansip224r1() ecc.Curve {
	initonce.Do(initAll)
	return ansip224r1
}

func Ansip384r1() ecc.Curve {
	initonce.Do(initAll)
	return ansip384r1
}

func Ansip521r1() ecc.Curve {
	initonce.Do(initAll)
	return ansip521r1
}

// binary fields

func Ansit163k1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return ansit163k1
}

func Ansit163r1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return ansit163r1
}

func Ansit163r2() ecc.BinaryCurve {
	initonce.Do(initAll)
	return ansit163r2
}

func Ansit193r1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return ansit193r1
}

func Ansit193r2() ecc.BinaryCurve {
	initonce.Do(initAll)
	return ansit193r2
}

func Ansit233k1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return ansit233k1
}

func Ansit233r1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return ansit233r1
}

func Ansit239k1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return ansit239k1
}

func Ansit283k1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return ansit283k1
}

func Ansit283r1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return ansit283r1
}

func Ansit409k1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return ansit409k1
}

func Ansit409r1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return ansit409r1
}

func Ansit571k1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return ansit571k1
}

func Ansit571r1() ecc.BinaryCurve {
	initonce.Do(initAll)
	return ansit571r1
}
