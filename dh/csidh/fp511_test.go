package csidh

import (
	"math/big"
	"math/rand"
	"testing"

	"golang.org/x/sys/cpu"
)

func resetCPUFeatures() {
	hasBMI2 = cpu.X86.HasBMI2
	hasADXandBMI2 = cpu.X86.HasBMI2 && cpu.X86.HasADX
}

func testFp512Mul3Nominal(t *testing.T) {
	var multiplier64 uint64
	var mod big.Int

	// modulus: 2^512
	mod.SetUint64(1).Lsh(&mod, 512)

	for i := 0; i < numIter; i++ {
		multiplier64 = rand.Uint64()

		fV := randomFp()
		exp, _ := new(big.Int).SetString(fp2S(fV), 16)
		exp.Mul(exp, new(big.Int).SetUint64(multiplier64))
		// Truncate to 512 bits
		exp.Mod(exp, &mod)

		mul512(&fV, &fV, multiplier64)
		res, _ := new(big.Int).SetString(fp2S(fV), 16)

		if exp.Cmp(res) != 0 {
			t.Errorf("%X != %X", exp, res)
		}
	}
}

// Check if mul512 produces result
// z = x*y mod 2^512
func TestFp512Mul3_Nominal(t *testing.T) {
	hasBMI2 = false
	testFp512Mul3Nominal(t)

	resetCPUFeatures()
	testFp512Mul3Nominal(t)

}

func TestAddRdcRandom(t *testing.T) {
	for i := 0; i < numIter; i++ {
		a := randomFp()
		bigA, _ := new(big.Int).SetString(fp2S(a), 16)
		bigA.Mod(bigA, modulus)
		copy(a[:], intGetU64(bigA))

		b := randomFp()
		bigB, _ := new(big.Int).SetString(fp2S(b), 16)
		bigB.Mod(bigB, modulus)
		copy(b[:], intGetU64(bigB))

		addRdc(&a, &a, &b)
		bigRet, _ := new(big.Int).SetString(fp2S(a), 16)

		bigA.Add(bigA, bigB)
		bigA.Mod(bigA, modulus)

		if bigRet.Cmp(bigA) != 0 {
			t.Errorf("%X != %X", bigRet, bigA)
		}
	}
}

func TestAddRdcNominal(t *testing.T) {
	var res fp

	tmp := oneFp512
	addRdc(&res, &tmp, &p)
	if !eqFp(&res, &tmp) {
		t.Errorf("Wrong value\n%X", res)
	}

	tmp = zeroFp512
	addRdc(&res, &p, &p)
	if !eqFp(&res, &p) {
		t.Errorf("Wrong value\n%X", res)
	}

	tmp = fp{1, 1, 1, 1, 1, 1, 1, 1}
	addRdc(&res, &p, &tmp)
	if !eqFp(&res, &tmp) {
		t.Errorf("Wrong value\n%X", res)
	}

	tmp = fp{1, 1, 1, 1, 1, 1, 1, 1}
	exp := fp{2, 2, 2, 2, 2, 2, 2, 2}
	addRdc(&res, &tmp, &tmp)
	if !eqFp(&res, &exp) {
		t.Errorf("Wrong value\n%X", res)
	}
}

func TestFp512Sub3_Nominal(t *testing.T) {
	var ret fp
	var mod big.Int
	// modulus: 2^512
	mod.SetUint64(1).Lsh(&mod, 512)

	for i := 0; i < numIter; i++ {
		a := randomFp()
		bigA, _ := new(big.Int).SetString(fp2S(a), 16)
		b := randomFp()
		bigB, _ := new(big.Int).SetString(fp2S(b), 16)

		sub512(&ret, &a, &b)
		bigRet, _ := new(big.Int).SetString(fp2S(ret), 16)
		bigA.Sub(bigA, bigB)
		// Truncate to 512 bits
		bigA.Mod(bigA, &mod)

		if bigRet.Cmp(bigA) != 0 {
			t.Errorf("%X != %X", bigRet, bigA)
		}
	}
}

func TestFp512Sub3_DoesntReturnCarry(t *testing.T) {
	a := fp{}
	b := fp{
		0xFFFFFFFFFFFFFFFF, 1,
		0, 0,
		0, 0,
		0, 0}
	c := fp{
		0xFFFFFFFFFFFFFFFF, 2,
		0, 0,
		0, 0,
		0, 0}

	if sub512(&a, &b, &c) != 1 {
		t.Error("Carry not returned")
	}
}

func TestFp512Sub3_ReturnsCarry(t *testing.T) {
	a := fp{}
	b := fp{
		0xFFFFFFFFFFFFFFFF, 2,
		0, 0,
		0, 0,
		0, 0}
	c := fp{
		0xFFFFFFFFFFFFFFFF, 1,
		0, 0,
		0, 0,
		0, 0}

	if sub512(&a, &b, &c) != 0 {
		t.Error("Carry not returned")
	}
}

func TestCswap(t *testing.T) {
	arg1 := randomFp()
	arg2 := randomFp()

	arg1cpy := arg1
	cswap512(&arg1, &arg2, 0)
	if !eqFp(&arg1, &arg1cpy) {
		t.Error("cswap swapped")
	}

	arg1cpy = arg1
	cswap512(&arg1, &arg2, 1)
	if eqFp(&arg1, &arg1cpy) {
		t.Error("cswap didn't swapped")
	}

	arg1cpy = arg1
	cswap512(&arg1, &arg2, 0xF2)
	if eqFp(&arg1, &arg1cpy) {
		t.Error("cswap didn't swapped")
	}
}

func TestSubRdc(t *testing.T) {
	var res fp

	// 1 - 1 mod P
	tmp := oneFp512
	subRdc(&res, &tmp, &tmp)
	if !eqFp(&res, &zeroFp512) {
		t.Errorf("Wrong value\n%X", res)
	}
	zero(&res)

	// 0 - 1 mod P
	exp := p
	exp[0]--

	subRdc(&res, &zeroFp512, &oneFp512)
	if !eqFp(&res, &exp) {
		t.Errorf("Wrong value\n%X\n%X", res, exp)
	}
	zero(&res)

	// P - (P-1)
	pMinusOne := p
	pMinusOne[0]--
	subRdc(&res, &p, &pMinusOne)
	if !eqFp(&res, &oneFp512) {
		t.Errorf("Wrong value\n[%X != %X]", res, oneFp512)
	}
	zero(&res)

	subRdc(&res, &p, &oneFp512)
	if !eqFp(&res, &pMinusOne) {
		t.Errorf("Wrong value\n[%X != %X]", res, pMinusOne)
	}
}

func testMulRdc(t *testing.T) {
	var res fp
	var m1 = fp{
		0x85E2579C786882D0, 0x4E3433657E18DA95,
		0x850AE5507965A0B3, 0xA15BC4E676475964}
	var m2 = fp{
		0x85E2579C786882CF, 0x4E3433657E18DA95,
		0x850AE5507965A0B3, 0xA15BC4E676475964}

	// Expected
	var m1m1 = fp{
		0xAEBF46E92C88A4B4, 0xCFE857977B946347,
		0xD3B264FF08493901, 0x6EEB3D23746B6C7C,
		0xC0CA874A349D64B4, 0x7AD4A38B406F8504,
		0x38B6B6CEB82472FB, 0x1587015FD7DDFC7D}
	var m1m2 = fp{
		0x51534771258C4624, 0x2BFEDE86504E2160,
		0xE8127D5E9329670B, 0x0C84DBD584491D75,
		0x656C73C68B16E38C, 0x01C0DA470B30B8DE,
		0x2532E3903EAA950B, 0x3F2C28EA97FE6FEC}

	// 0*0
	tmp := zeroFp512
	mulRdc(&res, &tmp, &tmp)
	if !eqFp(&res, &tmp) {
		t.Errorf("Wrong value\n%X", res)
	}

	// 1*m1 == m1
	zero(&res)
	mulRdc(&res, &m1, &one)
	if !eqFp(&res, &m1) {
		t.Errorf("Wrong value\n%X", res)
	}

	// m1*m2 < p
	zero(&res)
	mulRdc(&res, &m1, &m2)
	if !eqFp(&res, &m1m2) {
		t.Errorf("Wrong value\n%X", res)
	}

	// m1*m1 > p
	zero(&res)
	mulRdc(&res, &m1, &m1)
	if !eqFp(&res, &m1m1) {
		t.Errorf("Wrong value\n%X", res)
	}
}

func TestMulRdc(t *testing.T) {
	hasADXandBMI2 = false
	testMulRdc(t)

	resetCPUFeatures()
	testMulRdc(t)
}

func TestModExp(t *testing.T) {
	var resExp, base, exp big.Int
	var baseFp, expFp, resFp, resFpExp fp

	for i := 0; i < numIter; i++ {
		// Perform modexp with reference implementation
		// in Montgomery domain
		base.SetString(fp2S(randomFp()), 16)
		exp.SetString(fp2S(randomFp()), 16)
		resExp.Exp(&base, &exp, modulus)
		toMont(&base, true)
		toMont(&resExp, true)

		// Convert to fp
		copy(baseFp[:], intGetU64(&base))
		copy(expFp[:], intGetU64(&exp))
		copy(resFpExp[:], intGetU64(&resExp))

		// Perform modexp with our implementation
		modExpRdc512(&resFp, &baseFp, &expFp)

		if !eqFp(&resFp, &resFpExp) {
			t.Errorf("Wrong value\n%X!=%X", resFp, intGetU64(&resExp))
		}
	}
}

// Test uses Euler's Criterion
func TestIsNonQuadRes(t *testing.T) {
	var n, nMont big.Int
	var pm1o2, rawP big.Int
	var nMontFp fp

	// (p-1)/2
	pm1o2.SetString("0x32da4747ba07c4dffe455868af1f26255a16841d76e446212d7dfe63499164e6d3d56362b3f9aa83a8b398660f85a792e1390dfa2bd6541a8dc0dc8299e3643d", 0)
	// modulus value (not in montgomery)
	rawP.SetString("0x65b48e8f740f89bffc8ab0d15e3e4c4ab42d083aedc88c425afbfcc69322c9cda7aac6c567f35507516730cc1f0b4f25c2721bf457aca8351b81b90533c6c87b", 0)

	// There is 641 quadratic residues in this range
	for i := uint64(1); i < uint64(numIter); i++ {
		n.SetUint64(i)
		n.Exp(&n, &pm1o2, &rawP)
		// exp == 1 iff n is quadratic non-residue
		exp := n.Cmp(big.NewInt(1))
		if exp < 0 {
			panic("Should never happen")
		}

		nMont.SetUint64(i)
		toMont(&nMont, true)
		copy(nMontFp[:], intGetU64(&nMont))
		ret := nMontFp.isNonQuadRes()

		if ret != exp {
			toMont(&nMont, false)
			t.Errorf("Test failed for value %s", nMont.Text(10))
		}
	}
}

func TestCheckSmaller(t *testing.T) {
	// p-1
	var pMin1 = p
	pMin1[0]--

	// p-1 < p => 1
	if !isLess(&pMin1, &p) {
		t.Error("pMin1>p")
	}

	// p < p-1 => 0
	if isLess(&p, &pMin1) {
		t.Error("p>pMin1")
	}

	// p == p => 0
	if isLess(&p, &p) {
		t.Error("p==p")
	}
}

func BenchmarkFp512Sub(b *testing.B) {
	var arg1 fp
	arg2, arg3 := randomFp(), randomFp()
	for n := 0; n < b.N; n++ {
		sub512(&arg1, &arg2, &arg3)
	}
}

func BenchmarkFp512Mul(b *testing.B) {
	var arg1 = rand.Uint64()
	arg2, arg3 := randomFp(), randomFp()
	for n := 0; n < b.N; n++ {
		mul512(&arg2, &arg3, arg1)
	}
}

func BenchmarkCSwap(b *testing.B) {
	arg1 := randomFp()
	arg2 := randomFp()
	for n := 0; n < b.N; n++ {
		cswap512(&arg1, &arg2, uint8(n%2))
	}
}

func BenchmarkAddRdc(b *testing.B) {
	var res fp
	arg1 := randomFp()
	arg2 := randomFp()

	for n := 0; n < b.N; n++ {
		addRdc(&res, &arg1, &arg2)
	}
}

func BenchmarkSubRdc(b *testing.B) {
	arg1 := randomFp()
	arg2 := randomFp()
	var res fp
	for n := 0; n < b.N; n++ {
		subRdc(&res, &arg1, &arg2)
	}
}

func BenchmarkModExpRdc(b *testing.B) {
	arg1 := randomFp()
	arg2 := randomFp()
	var res fp
	for n := 0; n < b.N; n++ {
		modExpRdc512(&res, &arg1, &arg2)
	}
}

func BenchmarkMulGeneric(b *testing.B) {
	arg1 := randomFp()
	arg2 := randomFp()
	var res fp
	for n := 0; n < b.N; n++ {
		mulGeneric(&res, &arg1, &arg2)
	}
}

func BenchmarkMulBmiAsm(b *testing.B) {
	arg1 := randomFp()
	arg2 := randomFp()
	var res fp
	for n := 0; n < b.N; n++ {
		mulRdc(&res, &arg1, &arg2)
	}
}

func BenchmarkMulGenAsm(b *testing.B) {
	arg1 := randomFp()
	arg2 := randomFp()
	var res fp
	hasADXandBMI2 = false
	for n := 0; n < b.N; n++ {
		mulRdc(&res, &arg1, &arg2)
	}

	resetCPUFeatures()
}
