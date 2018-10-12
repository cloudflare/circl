package p751

import (
	"bytes"
	. "github.com/cloudflare/circl/dh/sidh/internal/isogeny"
	"testing"
	"testing/quick"
)

func TestOne(t *testing.T) {
	var tmp Fp2Element

	kFieldOps.Mul(&tmp, &P751_OneFp2, &affine_xP)
	if !VartimeEqFp2(&tmp, &affine_xP) {
		t.Error("Not equal 1")
	}
}

// This test is here only to ensure that ScalarMult helper works correctly
func TestScalarMultVersusSage(t *testing.T) {
	var xP ProjectivePoint

	xP = ProjectivePoint{X: affine_xP, Z: P751_OneFp2}
	xP = ScalarMult(&curve, &xP, mScalarBytes[:]) // = x([m]P)
	affine_xQ := xP.ToAffine(kCurveOps)
	if !VartimeEqFp2(&affine_xaP, affine_xQ) {
		t.Error("\nExpected\n", affine_xaP, "\nfound\n", affine_xQ)
	}
}

func Test_jInvariant(t *testing.T) {
	var curve = ProjectiveCurveParameters{A: curve_A, C: curve_C}
	var jbufRes [P751_SharedSecretSize]byte
	var jbufExp [P751_SharedSecretSize]byte
	// Computed using Sage
	// j = 3674553797500778604587777859668542828244523188705960771798425843588160903687122861541242595678107095655647237100722594066610650373491179241544334443939077738732728884873568393760629500307797547379838602108296735640313894560419*i + 3127495302417548295242630557836520229396092255080675419212556702820583041296798857582303163183558315662015469648040494128968509467224910895884358424271180055990446576645240058960358037224785786494172548090318531038910933793845
	var known_j = Fp2Element{
		A: FpElement{0xc7a8921c1fb23993, 0xa20aea321327620b, 0xf1caa17ed9676fa8, 0x61b780e6b1a04037, 0x47784af4c24acc7a, 0x83926e2e300b9adf, 0xcd891d56fae5b66, 0x49b66985beb733bc, 0xd4bcd2a473d518f, 0xe242239991abe224, 0xa8af5b20f98672f8, 0x139e4d4e4d98},
		B: FpElement{0xb5b52a21f81f359, 0x715e3a865db6d920, 0x9bac2f9d8911978b, 0xef14acd8ac4c1e3d, 0xe81aacd90cfb09c8, 0xaf898288de4a09d9, 0xb85a7fb88c5c4601, 0x2c37c3f1dd303387, 0x7ad3277fe332367c, 0xd4cbee7f25a8e6f8, 0x36eacbe979eaeffa, 0x59eb5a13ac33},
	}
	kCurveOps.Jinvariant(&curve, jbufRes[:])
	kCurveOps.Fp2ToBytes(jbufExp[:], &known_j)

	if !bytes.Equal(jbufRes[:], jbufExp[:]) {
		t.Error("Computed incorrect j-invariant: found\n", jbufRes, "\nexpected\n", jbufExp)
	}
}

func TestProjectivePointVartimeEq(t *testing.T) {
	var xP ProjectivePoint

	xP = ProjectivePoint{X: affine_xP, Z: P751_OneFp2}
	xQ := xP
	// Scale xQ, which results in the same projective point
	kFieldOps.Mul(&xQ.X, &xQ.X, &curve_A)
	kFieldOps.Mul(&xQ.Z, &xQ.Z, &curve_A)
	if !VartimeEqProjFp2(&xP, &xQ) {
		t.Error("Expected the scaled point to be equal to the original")
	}
}

func TestPointDoubleVersusSage(t *testing.T) {
	var curve = ProjectiveCurveParameters{A: curve_A, C: curve_C}
	var params = kCurveOps.CalcCurveParamsEquiv4(&curve)
	var xP ProjectivePoint

	xP = ProjectivePoint{X: affine_xP, Z: P751_OneFp2}
	kCurveOps.Pow2k(&xP, &params, 1)
	affine_xQ := xP.ToAffine(kCurveOps)
	if !VartimeEqFp2(affine_xQ, &affine_xP2) {
		t.Error("\nExpected\n", affine_xP2, "\nfound\n", affine_xQ)
	}
}

func TestPointMul4VersusSage(t *testing.T) {
	var params = kCurveOps.CalcCurveParamsEquiv4(&curve)
	var xP ProjectivePoint

	xP = ProjectivePoint{X: affine_xP, Z: P751_OneFp2}
	kCurveOps.Pow2k(&xP, &params, 2)
	affine_xQ := xP.ToAffine(kCurveOps)
	if !VartimeEqFp2(affine_xQ, &affine_xP4) {
		t.Error("\nExpected\n", affine_xP4, "\nfound\n", affine_xQ)
	}
}

func TestPointMul9VersusSage(t *testing.T) {
	var params = kCurveOps.CalcCurveParamsEquiv3(&curve)
	var xP ProjectivePoint

	xP = ProjectivePoint{X: affine_xP, Z: P751_OneFp2}
	kCurveOps.Pow3k(&xP, &params, 2)
	affine_xQ := xP.ToAffine(kCurveOps)
	if !VartimeEqFp2(affine_xQ, &affine_xP9) {
		t.Error("\nExpected\n", affine_xP9, "\nfound\n", affine_xQ)
	}
}

func TestPointPow2kVersusScalarMult(t *testing.T) {
	var xP, xQ, xR ProjectivePoint
	var params = kCurveOps.CalcCurveParamsEquiv4(&curve)

	xP = ProjectivePoint{X: affine_xP, Z: P751_OneFp2}
	xQ = xP
	kCurveOps.Pow2k(&xQ, &params, 5)
	xR = ScalarMult(&curve, &xP, []byte{32})
	affine_xQ := xQ.ToAffine(kCurveOps) // = x([32]P)
	affine_xR := xR.ToAffine(kCurveOps) // = x([32]P)

	if !VartimeEqFp2(affine_xQ, affine_xR) {
		t.Error("\nExpected\n", affine_xQ, "\nfound\n", affine_xR)
	}
}

func TestRecoverCoordinateA(t *testing.T) {
	var cparam ProjectiveCurveParameters
	// Vectors generated with SIKE reference implementation
	var a = Fp2Element{
		A: FpElement{0x9331D9C5AAF59EA4, 0xB32B702BE4046931, 0xCEBB333912ED4D34, 0x5628CE37CD29C7A2, 0x0BEAC5ED48B7F58E, 0x1FB9D3E281D65B07, 0x9C0CFACC1E195662, 0xAE4BCE0F6B70F7D9, 0x59E4E63D43FE71A0, 0xEF7CE57560CC8615, 0xE44A8FB7901E74E8, 0x000069D13C8366D1},
		B: FpElement{0xF6DA1070279AB966, 0xA78FB0CE7268C762, 0x19B40F044A57ABFA, 0x7AC8EE6160C0C233, 0x93D4993442947072, 0x757D2B3FA4E44860, 0x073A920F8C4D5257, 0x2031F1B054734037, 0xDEFAA1D2406555CD, 0x26F9C70E1496BE3D, 0x5B3F335A0A4D0976, 0x000013628B2E9C59}}
	var affine_xP = Fp2Element{
		A: FpElement{0xea6b2d1e2aebb250, 0x35d0b205dc4f6386, 0xb198e93cb1830b8d, 0x3b5b456b496ddcc6, 0x5be3f0d41132c260, 0xce5f188807516a00, 0x54f3e7469ea8866d, 0x33809ef47f36286, 0x6fa45f83eabe1edb, 0x1b3391ae5d19fd86, 0x1e66daf48584af3f, 0xb430c14aaa87},
		B: FpElement{0x97b41ebc61dcb2ad, 0x80ead31cb932f641, 0x40a940099948b642, 0x2a22fd16cdc7fe84, 0xaabf35b17579667f, 0x76c1d0139feb4032, 0x71467e1e7b1949be, 0x678ca8dadd0d6d81, 0x14445daea9064c66, 0x92d161eab4fa4691, 0x8dfbb01b6b238d36, 0x2e3718434e4e}}
	var affine_xQ = Fp2Element{
		A: FpElement{0xb055cf0ca1943439, 0xa9ff5de2fa6c69ed, 0x4f2761f934e5730a, 0x61a1dcaa1f94aa4b, 0xce3c8fadfd058543, 0xeac432aaa6701b8e, 0x8491d523093aea8b, 0xba273f9bd92b9b7f, 0xd8f59fd34439bb5a, 0xdc0350261c1fe600, 0x99375ab1eb151311, 0x14d175bbdbc5},
		B: FpElement{0xffb0ef8c2111a107, 0x55ceca3825991829, 0xdbf8a1ccc075d34b, 0xb8e9187bd85d8494, 0x670aa2d5c34a03b0, 0xef9fe2ed2b064953, 0xc911f5311d645aee, 0xf4411f409e410507, 0x934a0a852d03e1a8, 0xe6274e67ae1ad544, 0x9f4bc563c69a87bc, 0x6f316019681e}}
	var affine_xQmP = Fp2Element{
		A: FpElement{0x6ffb44306a153779, 0xc0ffef21f2f918f3, 0x196c46d35d77f778, 0x4a73f80452edcfe6, 0x9b00836bce61c67f, 0x387879418d84219e, 0x20700cf9fc1ec5d1, 0x1dfe2356ec64155e, 0xf8b9e33038256b1c, 0xd2aaf2e14bada0f0, 0xb33b226e79a4e313, 0x6be576fad4e5},
		B: FpElement{0x7db5dbc88e00de34, 0x75cc8cb9f8b6e11e, 0x8c8001c04ebc52ac, 0x67ef6c981a0b5a94, 0xc3654fbe73230738, 0xc6a46ee82983ceca, 0xed1aa61a27ef49f0, 0x17fe5a13b0858fe0, 0x9ae0ca945a4c6b3c, 0x234104a218ad8878, 0xa619627166104394, 0x556a01ff2e7e}}

	cparam.C = P751_OneFp2
	kCurveOps.RecoverCoordinateA(&cparam, &affine_xP, &affine_xQ, &affine_xQmP)

	// Check A is correct
	if !VartimeEqFp2(&cparam.A, &a) {
		t.Error("\nExpected\n", a, "\nfound\n", cparam.A)
	}

	// Check C is not changed
	if !VartimeEqFp2(&cparam.C, &P751_OneFp2) {
		t.Error("\nExpected\n", cparam.C, "\nfound\n", P751_OneFp2)
	}
}

func TestR2LVersusSage(t *testing.T) {
	var xR ProjectivePoint

	sageAffine_xR := Fp2Element{
		A: FpElement{0x729465ba800d4fd5, 0x9398015b59e514a1, 0x1a59dd6be76c748e, 0x1a7db94eb28dd55c, 0x444686e680b1b8ec, 0xcc3d4ace2a2454ff, 0x51d3dab4ec95a419, 0xc3b0f33594acac6a, 0x9598a74e7fd44f8a, 0x4fbf8c638f1c2e37, 0x844e347033052f51, 0x6cd6de3eafcf},
		B: FpElement{0x85da145412d73430, 0xd83c0e3b66eb3232, 0xd08ff2d453ec1369, 0xa64aaacfdb395b13, 0xe9cba211a20e806e, 0xa4f80b175d937cfc, 0x556ce5c64b1f7937, 0xb59b39ea2b3fdf7a, 0xc2526b869a4196b3, 0x8dad90bca9371750, 0xdfb4a30c9d9147a2, 0x346d2130629b}}
	xR = kCurveOps.ScalarMul3Pt(&curve, &threePointLadderInputs[0], &threePointLadderInputs[1], &threePointLadderInputs[2], uint(len(mScalarBytes)*8), mScalarBytes[:])
	affine_xR := xR.ToAffine(kCurveOps)

	if !VartimeEqFp2(affine_xR, &sageAffine_xR) {
		t.Error("\nExpected\n", sageAffine_xR, "\nfound\n", affine_xR)
	}
}

func TestPointTripleVersusAddDouble(t *testing.T) {
	tripleEqualsAddDouble := func(params GeneratedTestParams) bool {
		var P2, P3, P2plusP ProjectivePoint

		eqivParams4 := kCurveOps.CalcCurveParamsEquiv4(&params.Cparam)
		eqivParams3 := kCurveOps.CalcCurveParamsEquiv3(&params.Cparam)
		P2 = params.Point
		P3 = params.Point
		kCurveOps.Pow2k(&P2, &eqivParams4, 1)                   // = x([2]P)
		kCurveOps.Pow3k(&P3, &eqivParams3, 1)                   // = x([3]P)
		P2plusP = AddProjFp2(&P2, &params.Point, &params.Point) // = x([2]P + P)
		return VartimeEqProjFp2(&P3, &P2plusP)
	}

	if err := quick.Check(tripleEqualsAddDouble, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func BenchmarkThreePointLadder379BitScalar(b *testing.B) {
	var mScalarBytes = [...]uint8{84, 222, 146, 63, 85, 18, 173, 162, 167, 38, 10, 8, 143, 176, 93, 228, 247, 128, 50, 128, 205, 42, 15, 137, 119, 67, 43, 3, 61, 91, 237, 24, 235, 12, 53, 96, 186, 164, 232, 223, 197, 224, 64, 109, 137, 63, 246, 4}

	for n := 0; n < b.N; n++ {
		kCurveOps.ScalarMul3Pt(&curve, &threePointLadderInputs[0], &threePointLadderInputs[1], &threePointLadderInputs[2], uint(len(mScalarBytes)*8), mScalarBytes[:])
	}
}

func BenchmarkR2L379BitScalar(b *testing.B) {
	var mScalarBytes = [...]uint8{84, 222, 146, 63, 85, 18, 173, 162, 167, 38, 10, 8, 143, 176, 93, 228, 247, 128, 50, 128, 205, 42, 15, 137, 119, 67, 43, 3, 61, 91, 237, 24, 235, 12, 53, 96, 186, 164, 232, 223, 197, 224, 64, 109, 137, 63, 246, 4}

	for n := 0; n < b.N; n++ {
		kCurveOps.ScalarMul3Pt(&curve, &threePointLadderInputs[0], &threePointLadderInputs[1], &threePointLadderInputs[2], uint(len(mScalarBytes)*8), mScalarBytes[:])
	}
}
