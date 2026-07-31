//go:build amd64 && !purego

package fourq

import (
	"math/big"
	"testing"
)

func fqDec(s string) *big.Int { n, _ := new(big.Int).SetString(s, 10); return n }

// TestFqLegacyMulUnderflow checks the folding of a negative
// c0 = a0*b0 - a1*b1 in the non-BMI2 implementation of _fqMulLeg. The operands
// below are crafted so that the wrapped 4-limb difference has near-zero low
// limbs, which used to make the reduction return c0 + 2 (mod p).
func TestFqLegacyMulUnderflow(t *testing.T) {
	for i, v := range []struct{ a0, a1, b0, b1 *big.Int }{
		{ // c0 = a0*b0 - a1*b1 < 0
			fqDec("1040772936761"), fqDec("11408370363871524547533402319583468190"),
			fqDec("434439589176"), fqDec("139732579469944347347248239121883440209"),
		},
		{
			fqDec("105380810796"), fqDec("38510106373109501870162317539266385752"),
			fqDec("641520749049"), fqDec("36529003042230103456497810279788774518"),
		},
		{ // squaring: a0*a0 - a1*a1 < 0
			fqDec("951130727790"), fqDec("95223200964426662471948054802943153113"),
			fqDec("951130727790"), fqDec("95223200964426662471948054802943153113"),
		},
	} {
		a, b := &Fq{}, &Fq{}
		a.setBigInt(v.a0, v.a1)
		b.setBigInt(v.b0, v.b1)

		P := getModulus()
		want0 := new(big.Int).Sub(new(big.Int).Mul(v.a0, v.b0), new(big.Int).Mul(v.a1, v.b1))
		want1 := new(big.Int).Add(new(big.Int).Mul(v.a0, v.b1), new(big.Int).Mul(v.a1, v.b0))
		want0.Mod(want0, P)
		want1.Mod(want1, P)

		saved := hasBMI2
		hasBMI2 = false
		var c Fq
		fqMul(&c, a, b)
		if a == b {
			fqSqr(&c, a)
		}
		hasBMI2 = saved

		got0, got1 := c.toBigInt()
		if got0.Cmp(want0) != 0 || got1.Cmp(want1) != 0 {
			t.Errorf("case %d: legacy fqMul = (%v,%v), want (%v,%v)", i, got0, got1, want0, want1)
		}
	}
}

// TestFqLegacyMulReduced checks that the non-BMI2 implementation always returns
// elements below 2^127, as the rest of the fp/fq routines require. These
// operands used to produce c1 = 2^127+3, which then broke the following fqAdd.
func TestFqLegacyMulReduced(t *testing.T) {
	a, b := &Fq{}, &Fq{}
	a.setBigInt(fqDec("61001656442690109995816861220415634502"),
		fqDec("143175671162534831061383708417616629304"))
	b.setBigInt(fqDec("90181608331463849107831789068952927786"),
		fqDec("133642413020867947633558592306910754999"))

	saved := hasBMI2
	hasBMI2 = false
	var c, got Fq
	fqMul(&c, a, b)
	fqAdd(&got, &c, &c)
	hasBMI2 = saved

	if c[0][SizeFp-1]>>7 != 0 || c[1][SizeFp-1]>>7 != 0 {
		t.Errorf("legacy fqMul returned an unreduced element: %v", &c)
	}

	var wc, want Fq
	fqMulGeneric(&wc, a, b)
	fqAddGeneric(&want, &wc, &wc)
	got0, got1 := got.toBigInt()
	want0, want1 := want.toBigInt()
	if got0.Cmp(want0) != 0 || got1.Cmp(want1) != 0 {
		t.Errorf("fqAdd(fqMul(a,b)) = (%v,%v), want (%v,%v)", got0, got1, want0, want1)
	}
}

func TestFqLegacy(t *testing.T) {
	saved := hasBMI2
	defer func() { hasBMI2 = saved }()
	hasBMI2 = false
	t.Run("Add", func(t *testing.T) { testFqAdd(t, fqAdd) })
	t.Run("Sub", func(t *testing.T) { testFqSub(t, fqSub) })
	t.Run("Mul", func(t *testing.T) { testFqMul(t, fqMul) })
	t.Run("Sqr", func(t *testing.T) { testFqSqr(t, fqSqr) })
}
