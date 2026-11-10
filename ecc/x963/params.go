// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package x963

import (
	"sync"

	"github.com/cloudflare/circl/ecc"
	"github.com/cloudflare/circl/ecc/nist"
	"github.com/cloudflare/circl/ecc/secg"
)

var initonce sync.Once

var (
	ansip224r1 ecc.Curve
	ansip384r1 ecc.Curve
	ansip521r1 ecc.Curve

	// binary fields
	ansit163k1 ecc.BinaryCurve
	ansit163r1 ecc.BinaryCurve
	ansit163r2 ecc.BinaryCurve
	ansit193r1 ecc.BinaryCurve
	ansit193r2 ecc.BinaryCurve
	ansit233k1 ecc.BinaryCurve
	ansit233r1 ecc.BinaryCurve
	ansit239k1 ecc.BinaryCurve
	ansit283k1 ecc.BinaryCurve
	ansit283r1 ecc.BinaryCurve
	ansit409k1 ecc.BinaryCurve
	ansit409r1 ecc.BinaryCurve
	ansit571k1 ecc.BinaryCurve
	ansit571r1 ecc.BinaryCurve
)

func initAll() {
	// technically the "name" field is incorrect
	ansip224r1 = nist.P224()
	ansip384r1 = nist.P384()
	ansip521r1 = nist.P521()

	// binary fields
	ansit163k1 = nist.K163()
	ansit163r1 = secg.Sect163r1()
	ansit163r2 = nist.B163()

	ansit193r1 = secg.Sect193r1()
	ansit193r2 = secg.Sect193r2()

	ansit233k1 = nist.K233()
	ansit233r1 = nist.B233()

	ansit239k1 = secg.Sect239k1()

	ansit283k1 = nist.K283()
	ansit283r1 = nist.B283()

	ansit409k1 = nist.K409()
	ansit409r1 = nist.B409()

	ansit571k1 = nist.K571()
	ansit571r1 = nist.B571()
}
