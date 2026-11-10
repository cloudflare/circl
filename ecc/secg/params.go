// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package secg

import (
	"encoding/asn1"
	"sync"

	"github.com/cloudflare/circl/ecc"
	"github.com/cloudflare/circl/ecc/nist"
)

var initonce sync.Once

var (
	secp192r1 ecc.Curve
	secp224r1 ecc.Curve
	secp256r1 ecc.Curve
	secp384r1 ecc.Curve
	secp521r1 ecc.Curve

	// binary fields
	sect113r1 ecc.BinaryCurve
	sect113r2 ecc.BinaryCurve
	sect131r1 ecc.BinaryCurve
	sect131r2 ecc.BinaryCurve
	sect163k1 ecc.BinaryCurve
	sect163r1 ecc.BinaryCurve
	sect163r2 ecc.BinaryCurve
	sect193r1 ecc.BinaryCurve
	sect193r2 ecc.BinaryCurve
	sect233k1 ecc.BinaryCurve
	sect233r1 ecc.BinaryCurve
	sect239k1 ecc.BinaryCurve
	sect283k1 ecc.BinaryCurve
	sect283r1 ecc.BinaryCurve
	sect409k1 ecc.BinaryCurve
	sect409r1 ecc.BinaryCurve
	sect571k1 ecc.BinaryCurve
	sect571r1 ecc.BinaryCurve
)

//nolint:funlen // Keep the standardized curve parameter declarations together for review.
func initAll() {
	// technically the "name" field is incorrect since it's ambiguous
	secp192r1 = nist.P192()
	secp224r1 = nist.P224()
	secp256r1 = nist.P256()
	secp384r1 = nist.P384()
	secp521r1 = nist.P521()

	// binary fields
	sect113r1 = &ecc.BinaryCurveParams{
		Name:    "sect113r1",
		BitSize: 113,
		F:       ecc.F(113, 9, 0),
		A:       ecc.HexToBigInt("0x003088250ca6e7c7fe649ce85820f7"),
		B:       ecc.HexToBigInt("0x00e8bee4d3e2260744188be0e9c723"),
		Gx:      ecc.HexToBigInt("0x009d73616f35f4ab1407d73562c10f"),
		Gy:      ecc.HexToBigInt("0x00a52830277958ee84d1315ed31886"),
		N:       ecc.HexToBigInt("0x0100000000000000d9ccec8a39e56f"),
		H:       0x2,
		OidVal:  asn1.ObjectIdentifier{1, 3, 132, 0, 4},
	}

	sect113r2 = &ecc.BinaryCurveParams{
		Name:    "sect113r2",
		BitSize: 113,
		F:       ecc.F(113, 9, 0),
		A:       ecc.HexToBigInt("0x00689918dbec7e5a0dd6dfc0aa55c7"),
		B:       ecc.HexToBigInt("0x0095e9a9ec9b297bd4bf36e059184f"),
		Gx:      ecc.HexToBigInt("0x01a57a6a7b26ca5ef52fcdb8164797"),
		Gy:      ecc.HexToBigInt("0x00b3adc94ed1fe674c06e695baba1d"),
		N:       ecc.HexToBigInt("0x010000000000000108789b2496af93"),
		H:       0x2,
		OidVal:  asn1.ObjectIdentifier{1, 3, 132, 0, 5},
	}

	sect131r1 = &ecc.BinaryCurveParams{
		Name:    "sect131r1",
		BitSize: 131,
		F:       ecc.F(131, 8, 3, 2, 0),
		A:       ecc.HexToBigInt("0x07a11b09a76b562144418ff3ff8c2570b8"),
		B:       ecc.HexToBigInt("0x0217c05610884b63b9c6c7291678f9d341"),
		Gx:      ecc.HexToBigInt("0x0081baf91fdf9833c40f9c181343638399"),
		Gy:      ecc.HexToBigInt("0x078c6e7ea38c001f73c8134b1b4ef9e150"),
		N:       ecc.HexToBigInt("0x0400000000000000023123953a9464b54d"),
		H:       0x2,
		OidVal:  asn1.ObjectIdentifier{1, 3, 132, 0, 22},
	}

	sect131r2 = &ecc.BinaryCurveParams{
		Name:    "sect131r2",
		BitSize: 131,
		F:       ecc.F(131, 8, 3, 2, 0),
		A:       ecc.HexToBigInt("0x03e5a88919d7cafcbf415f07c2176573b2"),
		B:       ecc.HexToBigInt("0x04b8266a46c55657ac734ce38f018f2192"),
		Gx:      ecc.HexToBigInt("0x0356dcd8f2f95031ad652d23951bb366a8"),
		Gy:      ecc.HexToBigInt("0x0648f06d867940a5366d9e265de9eb240f"),
		N:       ecc.HexToBigInt("0x0400000000000000016954a233049ba98f"),
		H:       0x2,
		OidVal:  asn1.ObjectIdentifier{1, 3, 132, 0, 23},
	}

	sect163k1 = nist.K163()

	sect163r1 = &ecc.BinaryCurveParams{
		Name:    "sect163r1",
		BitSize: 163,
		F:       ecc.F(163, 7, 6, 3, 0),
		A:       ecc.HexToBigInt("0x07b6882caaefa84f9554ff8428bd88e246d2782ae2"),
		B:       ecc.HexToBigInt("0x0713612dcddcb40aab946bda29ca91f73af958afd9"),
		Gx:      ecc.HexToBigInt("0x0369979697ab43897789566789567f787a7876a654"),
		Gy:      ecc.HexToBigInt("0x00435edb42efafb2989d51fefce3c80988f41ff883"),
		N:       ecc.HexToBigInt("0x03ffffffffffffffffffff48aab689c29ca710279b"),
		H:       0x2,
		OidVal:  asn1.ObjectIdentifier{1, 3, 132, 0, 2},
	}

	sect163r2 = nist.B163()

	sect193r1 = &ecc.BinaryCurveParams{
		Name:    "sect193r1",
		BitSize: 193,
		F:       ecc.F(193, 15, 0),
		A:       ecc.HexToBigInt("0x0017858feb7a98975169e171f77b4087de098ac8a911df7b01"),
		B:       ecc.HexToBigInt("0x00fdfb49bfe6c3a89facadaa7a1e5bbc7cc1c2e5d831478814"),
		Gx:      ecc.HexToBigInt("0x01f481bc5f0ff84a74ad6cdf6fdef4bf6179625372d8c0c5e1"),
		Gy:      ecc.HexToBigInt("0x0025e399f2903712ccf3ea9e3a1ad17fb0b3201b6af7ce1b05"),
		N:       ecc.HexToBigInt("0x01000000000000000000000000c7f34a778f443acc920eba49"),
		H:       0x2,
		OidVal:  asn1.ObjectIdentifier{1, 3, 132, 0, 24},
	}

	sect193r2 = &ecc.BinaryCurveParams{
		Name:    "sect193r2",
		BitSize: 193,
		F:       ecc.F(193, 15, 0),
		A:       ecc.HexToBigInt("0x0163f35a5137c2ce3ea6ed8667190b0bc43ecd69977702709b"),
		B:       ecc.HexToBigInt("0x00c9bb9e8927d4d64c377e2ab2856a5b16e3efb7f61d4316ae"),
		Gx:      ecc.HexToBigInt("0x00d9b67d192e0367c803f39e1a7e82ca14a651350aae617e8f"),
		Gy:      ecc.HexToBigInt("0x01ce94335607c304ac29e7defbd9ca01f596f927224cdecf6c"),
		N:       ecc.HexToBigInt("0x010000000000000000000000015aab561b005413ccd4ee99d5"),
		H:       0x2,
		OidVal:  asn1.ObjectIdentifier{1, 3, 132, 0, 25},
	}

	sect233k1 = nist.K233()
	sect233r1 = nist.B233()

	sect239k1 = &ecc.BinaryCurveParams{
		Name:    "sect239k1",
		BitSize: 239,
		F:       ecc.F(239, 158, 0),
		A:       ecc.HexToBigInt("0x000000000000000000000000000000000000000000000000000000000000"),
		B:       ecc.HexToBigInt("0x000000000000000000000000000000000000000000000000000000000001"),
		Gx:      ecc.HexToBigInt("0x29a0b6a887a983e9730988a68727a8b2d126c44cc2cc7b2a6555193035dc"),
		Gy:      ecc.HexToBigInt("0x76310804f12e549bdb011c103089e73510acb275fc312a5dc6b76553f0ca"),
		N:       ecc.HexToBigInt("0x2000000000000000000000000000005a79fec67cb6e91f1c1da800e478a5"),
		H:       0x4,
		OidVal:  asn1.ObjectIdentifier{1, 3, 132, 0, 3},
	}

	sect283k1 = nist.K283()
	sect283r1 = nist.B283()

	sect409k1 = nist.K409()
	sect409r1 = nist.B409()

	sect571k1 = nist.K571()
	sect571r1 = nist.B571()
}
