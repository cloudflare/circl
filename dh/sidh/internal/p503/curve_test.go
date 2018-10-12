package p503

import (
	"bytes"
	. "github.com/cloudflare/circl/dh/sidh/internal/isogeny"
	"testing"
	"testing/quick"
)

func TestOne(t *testing.T) {
	var tmp Fp2Element

	kFieldOps.Mul(&tmp, &P503_OneFp2, &affine_xP)
	if !VartimeEqFp2(&tmp, &affine_xP) {
		t.Error("Not equal 1")
	}
}

// This test is here only to ensure that ScalarMult helper works correctly
func TestScalarMultVersusSage(t *testing.T) {
	var xP ProjectivePoint

	xP = ProjectivePoint{X: affine_xP, Z: P503_OneFp2}
	xP = ScalarMult(&curve, &xP, mScalarBytes[:]) // = x([m]P)
	affine_xQ := xP.ToAffine(kCurveOps)
	if !VartimeEqFp2(&affine_xaP, affine_xQ) {
		t.Error("\nExpected\n", affine_xaP, "\nfound\n", affine_xQ)
	}
}

func Test_jInvariant(t *testing.T) {
	var curve = ProjectiveCurveParameters{A: curve_A, C: curve_C}
	var jbufRes [P503_SharedSecretSize]byte
	var jbufExp [P503_SharedSecretSize]byte
	// Computed using Sage
	// j = 3674553797500778604587777859668542828244523188705960771798425843588160903687122861541242595678107095655647237100722594066610650373491179241544334443939077738732728884873568393760629500307797547379838602108296735640313894560419*i + 3127495302417548295242630557836520229396092255080675419212556702820583041296798857582303163183558315662015469648040494128968509467224910895884358424271180055990446576645240058960358037224785786494172548090318531038910933793845
	var known_j = Fp2Element{
		A: FpElement{0x2c441d03b72e27c, 0xf2c6748151dbf84, 0x3a774f6191070e, 0xa7c6212c9c800ba6, 0x23921b5cf09abc27, 0x9e1baefbb3cd4265, 0x8cd6a289f12e10dc, 0x3fa364128cf87e},
		B: FpElement{0xe7497ac2bf6b0596, 0x629ee01ad23bd039, 0x95ee11587a119fa7, 0x572fb28a24772269, 0x3c00410b6c71567e, 0xe681e83a345f8a34, 0x65d21b1d96bd2d52, 0x7889a47e58901},
	}
	kCurveOps.Jinvariant(&curve, jbufRes[:])
	kCurveOps.Fp2ToBytes(jbufExp[:], &known_j)

	if !bytes.Equal(jbufRes[:], jbufExp[:]) {
		t.Error("Computed incorrect j-invariant: found\n", jbufRes, "\nexpected\n", jbufExp)
	}
}

func TestProjectivePointVartimeEq(t *testing.T) {
	var xP ProjectivePoint

	xP = ProjectivePoint{X: affine_xP, Z: P503_OneFp2}
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

	xP = ProjectivePoint{X: affine_xP, Z: P503_OneFp2}
	kCurveOps.Pow2k(&xP, &params, 1)
	affine_xQ := xP.ToAffine(kCurveOps)
	if !VartimeEqFp2(affine_xQ, &affine_xP2) {
		t.Error("\nExpected\n", affine_xP2, "\nfound\n", affine_xQ)
	}
}

func TestPointMul4VersusSage(t *testing.T) {
	var params = kCurveOps.CalcCurveParamsEquiv4(&curve)
	var xP ProjectivePoint

	xP = ProjectivePoint{X: affine_xP, Z: P503_OneFp2}
	kCurveOps.Pow2k(&xP, &params, 2)
	affine_xQ := xP.ToAffine(kCurveOps)
	if !VartimeEqFp2(affine_xQ, &affine_xP4) {
		t.Error("\nExpected\n", affine_xP4, "\nfound\n", affine_xQ)
	}
}

func TestPointMul9VersusSage(t *testing.T) {
	var params = kCurveOps.CalcCurveParamsEquiv3(&curve)
	var xP ProjectivePoint

	xP = ProjectivePoint{X: affine_xP, Z: P503_OneFp2}
	kCurveOps.Pow3k(&xP, &params, 2)
	affine_xQ := xP.ToAffine(kCurveOps)
	if !VartimeEqFp2(affine_xQ, &affine_xP9) {
		t.Error("\nExpected\n", affine_xP9, "\nfound\n", affine_xQ)
	}
}

func TestPointPow2kVersusScalarMult(t *testing.T) {
	var xP, xQ, xR ProjectivePoint
	var params = kCurveOps.CalcCurveParamsEquiv4(&curve)

	xP = ProjectivePoint{X: affine_xP, Z: P503_OneFp2}
	xQ = xP
	kCurveOps.Pow2k(&xQ, &params, 5)
	xR = ScalarMult(&curve, &xP, []byte{32})
	affine_xQ := xQ.ToAffine(kCurveOps) // = x([32]P)
	affine_xR := xR.ToAffine(kCurveOps) // = x([32]P)

	if !VartimeEqFp2(affine_xQ, affine_xR) {
		t.Error("\nExpected\n", affine_xQ, "\nfound\n", affine_xR)
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

func BenchmarkThreePointLadder255BitScalar(b *testing.B) {
	var mScalarBytes = [...]uint8{203, 155, 185, 191, 131, 228, 50, 178, 207, 191, 61, 141, 174, 173, 207, 243, 159, 243, 46, 163, 19, 102, 69, 92, 36, 225, 0, 37, 114, 19, 191, 0}
	for n := 0; n < b.N; n++ {
		kCurveOps.ScalarMul3Pt(&curve, &threePointLadderInputs[0], &threePointLadderInputs[1], &threePointLadderInputs[2], 255, mScalarBytes[:])
	}
}
