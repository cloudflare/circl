package p503

import (
	. "github.com/cloudflare/circl/dh/sidh/internal/isogeny"
	"math/big"
	"testing"
	"testing/quick"
)

//------------------------------------------------------------------------------
// Extended Field
//------------------------------------------------------------------------------

func TestOneFp2ToBytes(t *testing.T) {
	var x = P503_OneFp2
	var xBytes [2 * P503_Bytelen]byte

	kCurveOps.Fp2ToBytes(xBytes[:], &x)
	if xBytes[0] != 1 {
		t.Error("Expected 1, got", xBytes[0])
	}
	for i := 1; i < 2*P503_Bytelen; i++ {
		if xBytes[i] != 0 {
			t.Error("Expected 0, got", xBytes[0])
		}
	}
}

func TestFp2ElementToBytesRoundTrip(t *testing.T) {
	roundTrips := func(x GeneratedTestParams) bool {
		var xBytes [2 * P503_Bytelen]byte
		var xPrime Fp2Element

		kCurveOps.Fp2ToBytes(xBytes[:], &x.ExtElem)
		kCurveOps.Fp2FromBytes(&xPrime, xBytes[:])
		return VartimeEqFp2(&xPrime, &x.ExtElem)
	}

	if err := quick.Check(roundTrips, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestFp2ElementMulDistributesOverAdd(t *testing.T) {
	mulDistributesOverAdd := func(x, y, z GeneratedTestParams) bool {
		// Compute t1 = (x+y)*z
		t1 := new(Fp2Element)
		kFieldOps.Add(t1, &x.ExtElem, &y.ExtElem)
		kFieldOps.Mul(t1, t1, &z.ExtElem)

		// Compute t2 = x*z + y*z
		t2 := new(Fp2Element)
		t3 := new(Fp2Element)
		kFieldOps.Mul(t2, &x.ExtElem, &z.ExtElem)
		kFieldOps.Mul(t3, &y.ExtElem, &z.ExtElem)
		kFieldOps.Add(t2, t2, t3)

		return VartimeEqFp2(t1, t2)
	}

	if err := quick.Check(mulDistributesOverAdd, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestFp2ElementMulIsAssociative(t *testing.T) {
	isAssociative := func(x, y, z GeneratedTestParams) bool {
		// Compute t1 = (x*y)*z
		t1 := new(Fp2Element)
		kFieldOps.Mul(t1, &x.ExtElem, &y.ExtElem)
		kFieldOps.Mul(t1, t1, &z.ExtElem)

		// Compute t2 = (y*z)*x
		t2 := new(Fp2Element)
		kFieldOps.Mul(t2, &y.ExtElem, &z.ExtElem)
		kFieldOps.Mul(t2, t2, &x.ExtElem)

		return VartimeEqFp2(t1, t2)
	}

	if err := quick.Check(isAssociative, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestFp2ElementSquareMatchesMul(t *testing.T) {
	sqrMatchesMul := func(x GeneratedTestParams) bool {
		// Compute t1 = (x*x)
		t1 := new(Fp2Element)
		kFieldOps.Mul(t1, &x.ExtElem, &x.ExtElem)

		// Compute t2 = x^2
		t2 := new(Fp2Element)
		kFieldOps.Square(t2, &x.ExtElem)

		return VartimeEqFp2(t1, t2)
	}

	if err := quick.Check(sqrMatchesMul, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestFp2ElementInv(t *testing.T) {
	inverseIsCorrect := func(x GeneratedTestParams) bool {
		z := new(Fp2Element)
		kFieldOps.Inv(z, &x.ExtElem)

		// Now z = (1/x), so (z * x) * x == x
		kFieldOps.Mul(z, z, &x.ExtElem)
		kFieldOps.Mul(z, z, &x.ExtElem)

		return VartimeEqFp2(z, &x.ExtElem)
	}

	// This is more expensive; run fewer tests
	var quickCheckConfig = &quick.Config{MaxCount: (1 << (8 + quickCheckScaleFactor))}
	if err := quick.Check(inverseIsCorrect, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestFp2ElementBatch3Inv(t *testing.T) {
	batchInverseIsCorrect := func(x1, x2, x3 GeneratedTestParams) bool {
		var x1Inv, x2Inv, x3Inv Fp2Element
		kFieldOps.Inv(&x1Inv, &x1.ExtElem)
		kFieldOps.Inv(&x2Inv, &x2.ExtElem)
		kFieldOps.Inv(&x3Inv, &x3.ExtElem)

		var y1, y2, y3 Fp2Element
		kCurveOps.Fp2Batch3Inv(&x1.ExtElem, &x2.ExtElem, &x3.ExtElem, &y1, &y2, &y3)

		return (VartimeEqFp2(&x1Inv, &y1) && VartimeEqFp2(&x2Inv, &y2) && VartimeEqFp2(&x3Inv, &y3))
	}

	// This is more expensive; run fewer tests
	var quickCheckConfig = &quick.Config{MaxCount: (1 << (5 + quickCheckScaleFactor))}
	if err := quick.Check(batchInverseIsCorrect, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

//------------------------------------------------------------------------------
// Prime Field
//------------------------------------------------------------------------------

func TestPrimeFieldElementMulVersusBigInt(t *testing.T) {
	mulMatchesBigInt := func(x, y primeFieldElement) bool {
		z := new(primeFieldElement)
		z.Mul(&x, &y)
		check := new(big.Int)
		check.Mul(toBigInt(&x.A), toBigInt(&y.A))
		check.Mod(check, p503BigIntPrime)
		return check.Cmp(toBigInt(&z.A)) == 0
	}

	if err := quick.Check(mulMatchesBigInt, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestPrimeFieldElementP34VersusBigInt(t *testing.T) {
	var p34, _ = new(big.Int).SetString("3293960789226779345209813229049836260623046691894590999611415869258960983005190308379728727886506087902151787597521914245745576582754898490288559357951", 10)
	p34MatchesBigInt := func(x primeFieldElement) bool {
		z := new(primeFieldElement)
		z.P34(&x)

		check := toBigInt(&x.A)
		check.Exp(check, p34, p503BigIntPrime)

		return check.Cmp(toBigInt(&z.A)) == 0
	}

	// This is more expensive; run fewer tests
	var quickCheckConfig = &quick.Config{MaxCount: (1 << (8 + quickCheckScaleFactor))}
	if err := quick.Check(p34MatchesBigInt, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestPrimeFieldElementToBigInt(t *testing.T) {
	// Chosen so that p < xR < 2p
	x := primeFieldElement{A: FpElement{
		1, 1, 1, 1, 1, 1, 1, 36028797018963968,
	},
	}
	// Computed using Sage:
	// sage: p = 2^e2 * 3^e3 - 1
	// sage: R = 2^512
	// sage: from_radix_64 = lambda xs: sum((xi * (2**64)**i for i,xi in enumerate(xs)))
	// sage: xR = from_radix_64([1]*7 + [2^55])
	// sage: assert(p < xR)
	// sage: assert(xR < 2*p)
	// sage: (xR / R) % p
	xBig, _ := new(big.Int).SetString("9018685569593152305590037326062904046918870374552508285127709347526265324701162612011653377441752634975109935373869185819144129719824212073345315986301", 10)
	if xBig.Cmp(toBigInt(&x.A)) != 0 {
		t.Error("Expected", xBig, "found", toBigInt(&x.A))
	}
}

func TestFpElementConditionalSwap(t *testing.T) {
	var one = FpElement{1, 1, 1, 1, 1, 1, 1, 1}
	var two = FpElement{2, 2, 2, 2, 2, 2, 2, 2}

	var x = one
	var y = two

	fp503ConditionalSwap(&x, &y, 0)

	if !(x == one && y == two) {
		t.Error("Found", x, "expected", one)
	}

	fp503ConditionalSwap(&x, &y, 1)

	if !(x == two && y == one) {
		t.Error("Found", x, "expected", two)
	}
}

func BenchmarkFp2ElementMul(b *testing.B) {
	z := &Fp2Element{A: bench_x, B: bench_y}
	w := new(Fp2Element)

	for n := 0; n < b.N; n++ {
		kFieldOps.Mul(w, z, z)
	}
}

func BenchmarkFp2ElementInv(b *testing.B) {
	z := &Fp2Element{A: bench_x, B: bench_y}
	w := new(Fp2Element)

	for n := 0; n < b.N; n++ {
		kFieldOps.Inv(w, z)
	}
}

func BenchmarkFp2ElementSquare(b *testing.B) {
	z := &Fp2Element{A: bench_x, B: bench_y}
	w := new(Fp2Element)

	for n := 0; n < b.N; n++ {
		kFieldOps.Square(w, z)
	}
}

func BenchmarkFp2ElementAdd(b *testing.B) {
	z := &Fp2Element{A: bench_x, B: bench_y}
	w := new(Fp2Element)

	for n := 0; n < b.N; n++ {
		kFieldOps.Add(w, z, z)
	}
}

func BenchmarkFp2ElementSub(b *testing.B) {
	z := &Fp2Element{A: bench_x, B: bench_y}
	w := new(Fp2Element)

	for n := 0; n < b.N; n++ {
		kFieldOps.Sub(w, z, z)
	}
}

func BenchmarkPrimeFieldElementMul(b *testing.B) {
	z := &primeFieldElement{A: bench_x}
	w := new(primeFieldElement)

	for n := 0; n < b.N; n++ {
		w.Mul(z, z)
	}
}

// --- field operation functions

func BenchmarkFp503Multiply(b *testing.B) {
	for n := 0; n < b.N; n++ {
		fp503Mul(&benchmarkFpElementX2, &bench_x, &bench_y)
	}
}

func BenchmarkFp503MontgomeryReduce(b *testing.B) {
	z := bench_z

	// This benchmark actually computes garbage, because
	// fp503MontgomeryReduce mangles its input, but since it's
	// constant-time that shouldn't matter for the benchmarks.
	for n := 0; n < b.N; n++ {
		fp503MontgomeryReduce(&benchmarkFpElement, &z)
	}
}

func BenchmarkFp503AddReduced(b *testing.B) {
	for n := 0; n < b.N; n++ {
		fp503AddReduced(&benchmarkFpElement, &bench_x, &bench_y)
	}
}

func BenchmarkFp503SubReduced(b *testing.B) {
	for n := 0; n < b.N; n++ {
		fp503SubReduced(&benchmarkFpElement, &bench_x, &bench_y)
	}
}

func BenchmarkFp503ConditionalSwap(b *testing.B) {
	x, y := bench_x, bench_y
	for n := 0; n < b.N; n++ {
		fp503ConditionalSwap(&x, &y, 1)
		fp503ConditionalSwap(&x, &y, 0)
	}
}

func BenchmarkFp503StrongReduce(b *testing.B) {
	x := bench_x
	for n := 0; n < b.N; n++ {
		fp503StrongReduce(&x)
	}
}

func BenchmarkFp503AddLazy(b *testing.B) {
	var z FpElement
	x, y := bench_x, bench_y
	for n := 0; n < b.N; n++ {
		fp503AddLazy(&z, &x, &y)
	}
}

func BenchmarkFp503X2AddLazy(b *testing.B) {
	x, y, z := bench_z, bench_z, bench_z
	for n := 0; n < b.N; n++ {
		fp503X2AddLazy(&x, &y, &z)
	}
}

func BenchmarkFp503X2SubLazy(b *testing.B) {
	x, y, z := bench_z, bench_z, bench_z
	for n := 0; n < b.N; n++ {
		fp503X2SubLazy(&x, &y, &z)
	}
}
