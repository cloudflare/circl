package p503

// Tools used for testing and debugging

import (
	. "github.com/cloudflare/circl/dh/sidh/internal/isogeny"
	"math/big"
	"math/rand"
	"reflect"
	"testing/quick"
)

/* -------------------------------------------------------------------------
   Underlying field configuration
   -------------------------------------------------------------------------*/
var (
	kFieldOps = FieldOperations()
	kParams   = &SidhParams{
		Op:      kFieldOps,
		OneFp2:  P503_OneFp2,
		HalfFp2: P503_HalfFp2,
		Bytelen: P503_Bytelen,
	}
	kCurveOps = &CurveOperations{Params: kParams}
)

/* -------------------------------------------------------------------------
   Configure testing/quick
   -------------------------------------------------------------------------*/
var (
	quickCheckScaleFactor = uint8(3)
	quickCheckConfig      = &quick.Config{MaxCount: (1 << (12 + quickCheckScaleFactor))}
)

/* -------------------------------------------------------------------------
   Structure used by tests
   -------------------------------------------------------------------------*/
type GeneratedTestParams struct {
	Point   ProjectivePoint
	Cparam  ProjectiveCurveParameters
	ExtElem Fp2Element
}

// A = 8752234765512331234913716743014562460822083005386252003333602919474238975785850965349950219277942402920758585086620525443539725921333735154674119646075*i + 6339624979889725406021454983012408976766782818694212228554611573314701271183857175866122275755278397694585249002282183018114967373119429936587424396917
var curve_A = Fp2Element{
	A: FpElement{0xd9816986a543095f, 0xa78cb1d7217bec21, 0x9595dc97b74ea70, 0x9120a1da6b42797d, 0x59ef9d903f74e47c, 0x4c58a4cdc45b6d0b, 0x816d5213aaf7ee6d, 0x3892fee6bb7343},
	B: FpElement{0x28c5288acbedf11b, 0x2143a438c86f6c68, 0x7cb5c4ae9c4c8e34, 0xb478aea445eed48b, 0x24d5c175776db478, 0x234582f8676c0ebe, 0x56234267b625fb08, 0x2c6e58d84b1192}}

// C = 10458464853790890798085664692909194316288127038910691163573355876336993883402795907795767791362493831987298578966325154262747805705783782806176495638177*i + 7770984753616185271325854825309278833018655051139367603077592443785629339985729818288672809062782315510526648882226172896710704020683893684611137718845
var curve_C = Fp2Element{
	A: FpElement{0xe05948236f2f913b, 0xc45da9ad1219a255, 0x7a568972a32fc1d0, 0x30f00bdd7071c3b1, 0x3b761b8dac2c98bc, 0x760f21b2179737b6, 0x13217e6656a13476, 0x2606b798e685aa},
	B: FpElement{0x1c0171f78820052e, 0x440b7f7087e57140, 0xe0510c07b31b0e96, 0xd0cf489b2ac4aea9, 0x4fb328f1c1fdf783, 0xb3b4912342951cb7, 0x70a4b64e81961c42, 0x33eed63cf07181}}

// x(P) = 9720237205826983370867050298878715935679372786589878620121159082290288918688002583435964840822877971257659901481591644347943354235932355923042390796255*i + 634577413124118560098123299804750904956499531431297942628887930019161512075536652691244843248133437326050395005054997679717801535474938466995392156605
var affine_xP = Fp2Element{
	A: FpElement{0xb606d954d407faf2, 0x58a1ef6cd213a203, 0x9823b55033e62f7b, 0x59cafc060d5e25a1, 0x529685f1753526fc, 0xc2eac3d219989c7d, 0xc5e30c75dfd343a0, 0x378285adc968a0},
	B: FpElement{0x6670f36db977b9da, 0xa07e2fdda5e1a7f0, 0xf367a7a722aed87d, 0x6c269e06d595cd10, 0x8379aa6092d87700, 0x57276ce3557ee7ae, 0xac8107bfbcd28993, 0x3d6f98869617a7}}

// x(Q) = 613162677562606602867371958793876971530136728660199185642812914351735322828980793298955764087721218995329689800176835576008483782305021671417330230966*i + 12939479853552958669415184882894789433224467828463058020095712989798268661016843892597050485554155971441665589419365957826417334087966365414056706471602
var affine_xQ = Fp2Element{
	A: FpElement{0xd3d14533cb0db45c, 0xdaf10b9f5fb037cf, 0x9562c31985823562, 0xb79b75e2bf5635a5, 0x83d38fb1669c2d9, 0x5e67117a35a57cbd, 0x4b94ed6c3cbf54a4, 0x3f47706b62778d},
	B: FpElement{0x1c766c0e7ed612d6, 0x2f3b42979e8efd86, 0xd82bac0006415ee7, 0x20cfe3bec0970042, 0x8f6628807e862bf9, 0xac4f82d13fddd9c5, 0x70b756e4bac1fa85, 0x350c02508e50dc}}

var affine_xPmQ = Fp2Element{
	A: FpElement{0x7295ac0e8a5531c8, 0xc02afbef6cdf51a8, 0x84d0c1bb8d80624f, 0x26abbf06c61e814b, 0xada277883fbdae07, 0x63b6739db68df3a7, 0x3554670381bcfcc6, 0x33419be255bbc6},
	B: FpElement{0xff9df35102da997a, 0xf9b920b2d8bd6210, 0x43d1514920e73bfb, 0x624c6fd6ef16da74, 0xeb535968ed0d1286, 0x9243e6ce29a636e6, 0x1849ed96cb7940e0, 0x1e4b495933b675}}

var affine_xP2 = Fp2Element{
	A: FpElement{0x4e1133c2b3855902, 0x875a775c67597fbb, 0xd17eb74254141abb, 0x1d5a464a4f3391f5, 0x24405c332811d007, 0x7e47e3eb489a7372, 0x65b130dfd9efe605, 0xfa69fac179803},
	B: FpElement{0x329f5322e1be51ee, 0x9004dca8132ebd6f, 0x7cd87e447ca8a7b6, 0x10a6ec02c38ce69e, 0x8cef2ed7d112ac46, 0x5f385a9fc4b57cd7, 0x68a366354fe7a32e, 0x2223c1455486ac}}

var affine_xP3 = Fp2Element{
	A: FpElement{0x74a2894cccbe287d, 0xa50e3ec842e13fce, 0xd42ea4d3f1b7ad0b, 0xa4943d50d306f99e, 0xf83e9c0955b08c33, 0xffd8e313402b9380, 0x967b315db0b2e6e, 0x3a0945883df3b4},
	B: FpElement{0xa9f610420a81c5ba, 0xbeb84b3ded2b4e75, 0x9fd6cea494470a70, 0x2fb0075e71900b0e, 0x63a0beb6abf3ca3d, 0xeb3e171798959f2e, 0x2209801eb702d40e, 0x36f8c4603e0fdb}}

var affine_xP4 = Fp2Element{
	A: FpElement{0x4eb695d34b46be8f, 0xfb5e76c58585f2d2, 0xa41f8aafa6dbb531, 0x4db82f5db5cfd144, 0x14dab0e3200cbba0, 0x430381706a279f81, 0xdf6707a57161f81, 0x44740f17197c3},
	B: FpElement{0xa2473705cdb6d4e9, 0xfa3cd67b9c15502c, 0xf0928166d0c5cee1, 0x6150aba0c874faaa, 0x6c0b18d6d92f9034, 0xcff71d340fc1e72e, 0x19a47027af917587, 0x25ed4bad443b8f}}

var affine_xP9 = Fp2Element{
	A: FpElement{0x112da30e288217e0, 0x5b336d527320a5f7, 0xbbf4d9403b68e3c6, 0x55eccb31c40b359c, 0x8907129ab69b3203, 0x69cc8c750125a915, 0xa41a38e6f530c0e1, 0xbe68e23af1b8d},
	B: FpElement{0x472c603765964213, 0xe4e64995b0769754, 0x4515583c74a6dd24, 0xff7c57f5818363a2, 0xbeaeb24662a92177, 0x8a54fa61fbf24c68, 0xa85542049eb45e12, 0x2b54caf655e285}}

// m = 3904534670189250445536401319770569077681088033069864532895
var mScalarBytes = [...]uint8{0x9f, 0x3b, 0xe7, 0xf9, 0xf4, 0x7c, 0xe6, 0xce, 0x79, 0x3e, 0x3d, 0x9f, 0x9f, 0x3b, 0xe7, 0xf9, 0xf4, 0x7c, 0xe6, 0xce, 0x79, 0x3e, 0x3d, 0x9f}

var affine_xaP = Fp2Element{
	A: FpElement{0x100a82c2be58e28b, 0x70ee7b57f40d9103, 0xb9f21d6327411cbb, 0x976b2a65166591cb, 0x35435bd4614ca404, 0x15f862a9c6f51469, 0x14d9ccfe634f374a, 0x31234988b0766c},
	B: FpElement{0x323a3a13113b35f8, 0xc949dad174586c8f, 0x1c5ed3b1263143c, 0x13ba9870c9b5bab8, 0x79fb89a31cfe7f19, 0xa8af6d4b5d947ed2, 0xcff00f80d7b67a56, 0xfdfcb136bff75}}

// Inputs for testing 3-point-ladder
var threePointLadderInputs = []ProjectivePoint{
	// x(P)
	ProjectivePoint{
		X: Fp2Element{
			A: FpElement{0x43941FA9244C059E, 0xD1F337D076941189, 0x6B6A8B3A8763C96A, 0x6DF569708D6C9482, 0x487EE5707A52F4AA, 0xDE396F6E2559689E, 0xE5EE3895A8991469, 0x2B0946695790A8},
			B: FpElement{0xAB552C0FDAED092E, 0x7DF895E43E7DCB1C, 0x35C700E761920C4B, 0xCC5807DD70DC117A, 0x0884039A5A8DB18A, 0xD04620B3D0738052, 0xA200835605138F10, 0x3FF2E59B2FDC6A}},
		Z: P503_OneFp2,
	},
	// x(Q)
	ProjectivePoint{
		X: Fp2Element{
			A: FpElement{0x77015826982BA1FD, 0x44024489673471E4, 0x1CAA2A5F4D5DA63B, 0xA183C07E50738C01, 0x8B97782D4E1A0DE6, 0x9B819522FBC38280, 0x0BDA46A937FB7B8A, 0x3B3614305914DF},
			B: FpElement{0xBF0366E97B3168D9, 0xAA522AC3879CEF0F, 0x0AF5EC975BD035C8, 0x1F26FEE7BBAC165C, 0xA0EE6A637724A6AB, 0xFB52101E36BA3A38, 0xD29CF5E376E17376, 0x1374A50DF57071}},
		Z: P503_OneFp2,
	},
	// x(P-Q)
	ProjectivePoint{
		X: Fp2Element{
			A: FpElement{0xD99279BBD41EA559, 0x35CF18E72F578214, 0x90473B1DC77F73E8, 0xBFFEA930B25D7F66, 0xFD558EA177B900B2, 0x7CFAD273A782A23E, 0x6B1F610822E0F611, 0x26D2D2EF9619B5},
			B: FpElement{0x534F83651CBCC75D, 0x591FB4757AED5D08, 0x0B04353D40BED542, 0x829A94703AAC9139, 0x0F9C2E6D7663EB5B, 0x5D2D0F90C283F746, 0x34C872AA12A7676E, 0x0ECDB605FBFA16}},
		Z: P503_OneFp2,
	},
}
var curve = ProjectiveCurveParameters{A: curve_A, C: curve_C}

// prime p503
var p503BigIntPrime, _ = new(big.Int).SetString("13175843156907117380839252916199345042492186767578363998445663477035843932020761233518914911546024351608607150390087656982982306331019593961154237431807", 10)

/* -------------------------------------------------------------------------
   Values used by benchmarking tools
   -------------------------------------------------------------------------*/

// Package-level storage for this field element is intended to deter
// compiler optimizations.
var (
	benchmarkFpElement   FpElement
	benchmarkFpElementX2 FpElementX2
	bench_x              = FpElement{17026702066521327207, 5108203422050077993, 10225396685796065916, 11153620995215874678, 6531160855165088358, 15302925148404145445, 1248821577836769963, 9789766903037985294, 7493111552032041328, 10838999828319306046, 18103257655515297935, 27403304611634}
	bench_y              = FpElement{4227467157325093378, 10699492810770426363, 13500940151395637365, 12966403950118934952, 16517692605450415877, 13647111148905630666, 14223628886152717087, 7167843152346903316, 15855377759596736571, 4300673881383687338, 6635288001920617779, 30486099554235}
	bench_z              = FpElementX2{1595347748594595712, 10854920567160033970, 16877102267020034574, 12435724995376660096, 3757940912203224231, 8251999420280413600, 3648859773438820227, 17622716832674727914, 11029567000887241528, 11216190007549447055, 17606662790980286987, 4720707159513626555, 12887743598335030915, 14954645239176589309, 14178817688915225254, 1191346797768989683, 12629157932334713723, 6348851952904485603, 16444232588597434895, 7809979927681678066, 14642637672942531613, 3092657597757640067, 10160361564485285723, 240071237}
)

/* -------------------------------------------------------------------------
   Helpers
   -------------------------------------------------------------------------*/

// Given xP = x(P), xQ = x(Q), and xPmQ = x(P-Q), compute xR = x(P+Q).
//
// Returns xR to allow chaining.  Safe to overlap xP, xQ, xR.
func AddProjFp2(xP, xQ, xPmQ *ProjectivePoint) ProjectivePoint {
	// Algorithm 1 of Costello-Smith.
	var v0, v1, v2, v3, v4 Fp2Element
	var xR ProjectivePoint
	kFieldOps.Add(&v0, &xP.X, &xP.Z) // X_P + Z_P
	kFieldOps.Sub(&v1, &xQ.X, &xQ.Z)
	kFieldOps.Mul(&v1, &v1, &v0)     // (X_Q - Z_Q)(X_P + Z_P)
	kFieldOps.Sub(&v0, &xP.X, &xP.Z) // X_P - Z_P
	kFieldOps.Add(&v2, &xQ.X, &xQ.Z)
	kFieldOps.Mul(&v2, &v2, &v0) // (X_Q + Z_Q)(X_P - Z_P)
	kFieldOps.Add(&v3, &v1, &v2)
	kFieldOps.Square(&v3, &v3) // 4(X_Q X_P - Z_Q Z_P)^2
	kFieldOps.Sub(&v4, &v1, &v2)
	kFieldOps.Square(&v4, &v4)         // 4(X_Q Z_P - Z_Q X_P)^2
	kFieldOps.Mul(&v0, &xPmQ.Z, &v3)   // 4X_{P-Q}(X_Q X_P - Z_Q Z_P)^2
	kFieldOps.Mul(&xR.Z, &xPmQ.X, &v4) // 4Z_{P-Q}(X_Q Z_P - Z_Q X_P)^2
	xR.X = v0
	return xR
}

// Given xP = x(P) and cached curve parameters Aplus2C = A + 2*C, C4 = 4*C,
// compute xQ = x([2]P).
//
// Returns xQ to allow chaining.  Safe to overlap xP, xQ.
func DoubleProjFp2(xP *ProjectivePoint, Aplus2C, C4 *Fp2Element) ProjectivePoint {
	// Algorithm 2 of Costello-Smith, amended to work with projective curve coefficients.
	var v1, v2, v3, xz4 Fp2Element
	var xQ ProjectivePoint
	kFieldOps.Add(&v1, &xP.X, &xP.Z) // (X+Z)^2
	kFieldOps.Square(&v1, &v1)
	kFieldOps.Sub(&v2, &xP.X, &xP.Z) // (X-Z)^2
	kFieldOps.Square(&v2, &v2)
	kFieldOps.Sub(&xz4, &v1, &v2)     // 4XZ = (X+Z)^2 - (X-Z)^2
	kFieldOps.Mul(&v2, &v2, C4)       // 4C(X-Z)^2
	kFieldOps.Mul(&xQ.X, &v1, &v2)    // 4C(X+Z)^2(X-Z)^2
	kFieldOps.Mul(&v3, &xz4, Aplus2C) // 4XZ(A + 2C)
	kFieldOps.Add(&v3, &v3, &v2)      // 4XZ(A + 2C) + 4C(X-Z)^2
	kFieldOps.Mul(&xQ.Z, &v3, &xz4)   // (4XZ(A + 2C) + 4C(X-Z)^2)4XZ
	// Now (xQ.x : xQ.z)
	//   = (4C(X+Z)^2(X-Z)^2 : (4XZ(A + 2C) + 4C(X-Z)^2)4XZ )
	//   = ((X+Z)^2(X-Z)^2 : (4XZ((A + 2C)/4C) + (X-Z)^2)4XZ )
	//   = ((X+Z)^2(X-Z)^2 : (4XZ((a + 2)/4) + (X-Z)^2)4XZ )
	return xQ
}

// Given x(P) and a scalar m in little-endian bytes, compute x([m]P) using the
// Montgomery ladder.  This is described in Algorithm 8 of Costello-Smith.
//
// This function's execution time is dependent only on the byte-length of the
// input scalar.  All scalars of the same input length execute in uniform time.
// The scalar can be padded with zero bytes to ensure a uniform length.
//
// Safe to overlap the source with the destination.
func ScalarMult(curve *ProjectiveCurveParameters, xP *ProjectivePoint, scalar []uint8) ProjectivePoint {
	var x0, x1, tmp ProjectivePoint
	var Aplus2C, C4 Fp2Element

	kFieldOps.Add(&Aplus2C, &curve.C, &curve.C) // = 2*C
	kFieldOps.Add(&C4, &Aplus2C, &Aplus2C)      // = 4*C
	kFieldOps.Add(&Aplus2C, &Aplus2C, &curve.A) // = 2*C + A

	x0.X = P503_OneFp2
	x1 = *xP

	// Iterate over the bits of the scalar, top to bottom
	prevBit := uint8(0)
	for i := len(scalar) - 1; i >= 0; i-- {
		scalarByte := scalar[i]
		for j := 7; j >= 0; j-- {
			bit := (scalarByte >> uint(j)) & 0x1
			kCurveOps.Params.Op.CondSwap(&x0.X, &x0.Z, &x1.X, &x1.Z, (bit ^ prevBit))
			//sProjectivePointConditionalSwap(&x0, &x1, (bit ^ prevBit))
			tmp = DoubleProjFp2(&x0, &Aplus2C, &C4)
			x1 = AddProjFp2(&x0, &x1, xP)
			x0 = tmp
			prevBit = bit
		}
	}
	// now prevBit is the lowest bit of the scalar
	kCurveOps.Params.Op.CondSwap(&x0.X, &x0.Z, &x1.X, &x1.Z, prevBit)
	return x0
}

// Returns true if lhs = rhs.  Takes variable time.
func VartimeEqFp2(lhs, rhs *Fp2Element) bool {
	a := *lhs
	b := *rhs

	fp503StrongReduce(&a.A)
	fp503StrongReduce(&a.B)
	fp503StrongReduce(&b.A)
	fp503StrongReduce(&b.B)

	eq := true
	for i := 0; i < len(a.A) && eq; i++ {
		eq = eq && (a.A[i] == b.A[i])
		eq = eq && (a.B[i] == b.B[i])
	}
	return eq
}

// Returns true if lhs = rhs.  Takes variable time.
func VartimeEqProjFp2(lhs, rhs *ProjectivePoint) bool {
	var t0, t1 Fp2Element
	kFieldOps.Mul(&t0, &lhs.X, &rhs.Z)
	kFieldOps.Mul(&t1, &lhs.Z, &rhs.X)
	return VartimeEqFp2(&t0, &t1)
}

func (GeneratedTestParams) generateFp2p503(rand *rand.Rand) Fp2Element {
	// Generation strategy: low limbs taken from [0,2^64); high limb
	// taken from smaller range
	//
	// Size hint is ignored since all elements are fixed size.
	//
	// Field elements taken in range [0,2p).  Emulate this by capping
	// the high limb by the top digit of 2*p-1:
	//
	// sage: (2*p-1).digits(2^64)[-1]
	// 36255204122967100
	//
	// This still allows generating values >= 2p, but hopefully that
	// excess is OK (and if it's not, we'll find out, because it's for
	// testing...)
	//
	highLimb := rand.Uint64() % 36255204122967100
	fpElementGen := func() FpElement {
		return FpElement{
			rand.Uint64(),
			rand.Uint64(),
			rand.Uint64(),
			rand.Uint64(),
			rand.Uint64(),
			rand.Uint64(),
			rand.Uint64(),
			highLimb,
		}
	}
	return Fp2Element{A: fpElementGen(), B: fpElementGen()}
}

func (c GeneratedTestParams) Generate(rand *rand.Rand, size int) reflect.Value {
	return reflect.ValueOf(
		GeneratedTestParams{
			ProjectivePoint{
				X: c.generateFp2p503(rand),
				Z: c.generateFp2p503(rand),
			},
			ProjectiveCurveParameters{
				A: c.generateFp2p503(rand),
				C: c.generateFp2p503(rand),
			},
			c.generateFp2p503(rand),
		})
}

func (x primeFieldElement) Generate(rand *rand.Rand, size int) reflect.Value {
	return reflect.ValueOf(primeFieldElement{A: new(GeneratedTestParams).generateFp2p503(rand).A})
}

// Convert an FpElement to a big.Int for testing.  Because this is only
// for testing, no big.Int to FpElement conversion is provided.
func radix64ToBigInt(x []uint64) *big.Int {
	radix := new(big.Int)
	// 2^64
	radix.UnmarshalText(([]byte)("18446744073709551616"))

	base := new(big.Int).SetUint64(1)
	val := new(big.Int).SetUint64(0)
	tmp := new(big.Int)

	for _, xi := range x {
		tmp.SetUint64(xi)
		tmp.Mul(tmp, base)
		val.Add(val, tmp)
		base.Mul(base, radix)
	}

	return val
}

func toBigInt(x *FpElement) *big.Int {
	// Convert from Montgomery form
	return toBigIntFromMontgomeryForm(x)
}

func toBigIntFromMontgomeryForm(x *FpElement) *big.Int {
	// Convert from Montgomery form
	a := FpElement{}
	aR := FpElementX2{}
	copy(aR[:], x[:])              // = a*R
	fp503MontgomeryReduce(&a, &aR) // = a mod p  in [0,2p)
	fp503StrongReduce(&a)          // = a mod p  in [0,p)
	return radix64ToBigInt(a[:])
}
