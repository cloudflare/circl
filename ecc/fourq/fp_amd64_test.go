//go:build amd64 && !purego
// +build amd64,!purego

package fourq

import (
	"math/big"
	"testing"
)

func TestFqMulLegacyCarryBug(t *testing.T) {
	defer func(b bool) { hasBMI2 = b }(hasBMI2)
	hasBMI2 = false // emulate a CPU without BMI2

	// x = 0 + (2^63)*i ; y = 1 + (2^64)*i  — all limbs canonical (< p), wire-encodable.
	x, y := &Fq{}, &Fq{}
	x[1][7] = 0x80 // x1 = 2^63
	y[0][0] = 0x01 // y0 = 1
	y[1][8] = 0x01 // y1 = 2^64

	got, want := &Fq{}, &Fq{}
	fqMul(got, x, y)         // legacy assembly path
	fqMulGeneric(want, x, y) // portable reference implementation

	got0, got1 := got.toBigInt()
	want0, want1 := want.toBigInt()
	if got0.Cmp(want0) != 0 || got1.Cmp(want1) != 0 {
		var d big.Int
		d.Sub(got0, want0).Mod(&d, getModulus())
		t.Fatalf("legacy fqMul wrong:\n got:  c0=%v c1=%v\n want: c0=%v c1=%v\n c0 error = +%v (mod p)",
			got0, got1, want0, want1, &d)
	}
}

func TestFqSqrLegacyCarryBug(t *testing.T) {
	defer func(b bool) { hasBMI2 = b }(hasBMI2)
	hasBMI2 = false

	// a = 0 + (2^127)*i — a weakly-reduced limb pattern (bit 127 set) of the kind
	// produced as intermediates inside point arithmetic; _fqSqrLeg = _fqMulLeg(c,a,a).
	a := &Fq{}
	a[1][15] = 0x80

	got, want := &Fq{}, &Fq{}
	fqSqr(got, a)
	fqSqrGeneric(want, a)

	got0, got1 := got.toBigInt()
	want0, want1 := want.toBigInt()
	if got0.Cmp(want0) != 0 || got1.Cmp(want1) != 0 {
		t.Fatalf("legacy fqSqr wrong:\n got:  c0=%v c1=%v\n want: c0=%v c1=%v",
			got0, got1, want0, want1)
	}
}
