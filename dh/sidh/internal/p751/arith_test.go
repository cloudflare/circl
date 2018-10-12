package p751

import (
	. "github.com/cloudflare/circl/dh/sidh/internal/isogeny"
	"math/big"
	"testing"
	"testing/quick"
)

func TestPrimeFieldElementToBigInt(t *testing.T) {
	// Chosen so that p < xR < 2p
	x := primeFieldElement{A: FpElement{
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 140737488355328,
	}}
	// Computed using Sage:
	// sage: p = 2^372 * 3^239 - 1
	// sage: R = 2^768
	// sage: from_radix_64 = lambda xs: sum((xi * (2**64)**i for i,xi in enumerate(xs)))
	// sage: xR = from_radix_64([1]*11 + [2^47])
	// sage: assert(p < xR)
	// sage: assert(xR < 2*p)
	// sage: (xR / R) % p
	xBig, _ := new(big.Int).SetString("4469946751055876387821312289373600189787971305258234719850789711074696941114031433609871105823930699680637820852699269802003300352597419024286385747737509380032982821081644521634652750355306547718505685107272222083450567982240", 10)
	if xBig.Cmp(toBigInt(&x.A)) != 0 {
		t.Error("Expected", xBig, "found", toBigInt(&x.A))
	}
}

//------------------------------------------------------------------------------
// Extended Field
//------------------------------------------------------------------------------

func TestOneFp2ToBytes(t *testing.T) {
	var x = P751_OneFp2
	var xBytes [188]byte

	kCurveOps.Fp2ToBytes(xBytes[:], &x)
	if xBytes[0] != 1 {
		t.Error("Expected 1, got", xBytes[0])
	}
	for i := 1; i < 188; i++ {
		if xBytes[i] != 0 {
			t.Error("Expected 0, got", xBytes[0])
		}
	}
}

func TestFp2ElementToBytesRoundTrip(t *testing.T) {
	roundTrips := func(x GeneratedTestParams) bool {
		var xBytes [188]byte
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
		check.Mod(check, cln16prime)

		return check.Cmp(toBigInt(&z.A)) == 0
	}

	if err := quick.Check(mulMatchesBigInt, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestPrimeFieldElementP34VersusBigInt(t *testing.T) {
	var p34, _ = new(big.Int).SetString("2588679435442326313244442059466701330356847411387267792529047419763669735170619711625720724140266678406138302904710050596300977994130638598261040117192787954244176710019728333589599932738193731745058771712747875468166412894207", 10)
	p34MatchesBigInt := func(x primeFieldElement) bool {
		z := new(primeFieldElement)
		z.P34(&x)

		check := toBigInt(&x.A)
		check.Exp(check, p34, cln16prime)

		return check.Cmp(toBigInt(&z.A)) == 0
	}

	// This is more expensive; run fewer tests
	var quickCheckConfig = &quick.Config{MaxCount: (1 << (8 + quickCheckScaleFactor))}
	if err := quick.Check(p34MatchesBigInt, quickCheckConfig); err != nil {
		t.Error(err)
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

func BenchmarkFp751Multiply(b *testing.B) {
	for n := 0; n < b.N; n++ {
		fp751Mul(&benchmarkFpElementX2, &bench_x, &bench_y)
	}
}

func BenchmarkFp751MontgomeryReduce(b *testing.B) {
	z := bench_z

	// This benchmark actually computes garbage, because
	// fp751MontgomeryReduce mangles its input, but since it's
	// constant-time that shouldn't matter for the benchmarks.
	for n := 0; n < b.N; n++ {
		fp751MontgomeryReduce(&benchmarkFpElement, &z)
	}
}

func BenchmarkFp751AddReduced(b *testing.B) {
	for n := 0; n < b.N; n++ {
		fp751AddReduced(&benchmarkFpElement, &bench_x, &bench_y)
	}
}

func BenchmarkFp751SubReduced(b *testing.B) {
	for n := 0; n < b.N; n++ {
		fp751SubReduced(&benchmarkFpElement, &bench_x, &bench_y)
	}
}

func BenchmarkFp751ConditionalSwap(b *testing.B) {
	x, y := bench_x, bench_y
	for n := 0; n < b.N; n++ {
		fp751ConditionalSwap(&x, &y, 1)
		fp751ConditionalSwap(&x, &y, 0)
	}
}

func BenchmarkFp751StrongReduce(b *testing.B) {
	x := bench_x
	for n := 0; n < b.N; n++ {
		fp751StrongReduce(&x)
	}
}

func BenchmarkFp751AddLazy(b *testing.B) {
	var z FpElement
	x, y := bench_x, bench_y
	for n := 0; n < b.N; n++ {
		fp751AddLazy(&z, &x, &y)
	}
}

func BenchmarkFp751X2AddLazy(b *testing.B) {
	x, y, z := bench_z, bench_z, bench_z
	for n := 0; n < b.N; n++ {
		fp751X2AddLazy(&x, &y, &z)
	}
}

func BenchmarkFp751X2SubLazy(b *testing.B) {
	x, y, z := bench_z, bench_z, bench_z
	for n := 0; n < b.N; n++ {
		fp751X2SubLazy(&x, &y, &z)
	}
}
