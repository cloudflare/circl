// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

// Package nist provides elliptic curves and their object identifiers.
//
// Custom curve operations may be variable time and must not be used with secret
// scalars. See the security documentation in package ecc.
package nist

import (
	"github.com/cloudflare/circl/ecc"
)

func P192() ecc.Curve {
	initonce.Do(initAll)
	return p192
}

func P224() ecc.Curve {
	initonce.Do(initAll)
	return p224
}

func P256() ecc.Curve {
	initonce.Do(initAll)
	return p256
}

func P384() ecc.Curve {
	initonce.Do(initAll)
	return p384
}

func P521() ecc.Curve {
	initonce.Do(initAll)
	return p521
}

// binary parameters

func K163() ecc.BinaryCurve {
	initonce.Do(initAll)
	return k163
}

func B163() ecc.BinaryCurve {
	initonce.Do(initAll)
	return b163
}

func K233() ecc.BinaryCurve {
	initonce.Do(initAll)
	return k233
}

func B233() ecc.BinaryCurve {
	initonce.Do(initAll)
	return b233
}

func K283() ecc.BinaryCurve {
	initonce.Do(initAll)
	return k283
}

func B283() ecc.BinaryCurve {
	initonce.Do(initAll)
	return b283
}

func K409() ecc.BinaryCurve {
	initonce.Do(initAll)
	return k409
}

func B409() ecc.BinaryCurve {
	initonce.Do(initAll)
	return b409
}

func K571() ecc.BinaryCurve {
	initonce.Do(initAll)
	return k571
}

func B571() ecc.BinaryCurve {
	initonce.Do(initAll)
	return b571
}
