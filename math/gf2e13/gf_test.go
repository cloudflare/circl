package gf2e13

import (
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

type (
	tadd     func(x, y Elt) Elt
	tmul     func(x, y Elt) Elt
	tsqr2    func(x Elt) Elt
	tsqrmul  func(x, y Elt) Elt
	tsqr2mul func(x, y Elt) Elt
	tinv     func(x Elt) Elt
	tdiv     func(x, y Elt) Elt
)

func assertEq(t *testing.T, a, b Elt) {
	t.Helper()
	if a != b {
		test.ReportError(t, b, a)
	}
}

func TestGeneric(t *testing.T) {
	t.Run("Add", func(t *testing.T) { testAdd(t, Add) })
	t.Run("Mul", func(t *testing.T) { testMul(t, Mul) })
	t.Run("sqr2", func(t *testing.T) { testSqr2(t, sqr2) })
	t.Run("sqrMul", func(t *testing.T) { testSqrMul(t, sqrMul) })
	t.Run("sqr2Mul", func(t *testing.T) { testSqr2Mul(t, sqr2Mul) })
	t.Run("Inv", func(t *testing.T) { testInv(t, Inv) })
	t.Run("Div", func(t *testing.T) { testDiv(t, Div) })
}

func testSqr2Mul(t *testing.T, sqr2Mul tsqr2mul) {
	assertEq(t, sqr2Mul(0, 0), 0)
	assertEq(t, sqr2Mul(0, 1), 0)
	assertEq(t, sqr2Mul(1, 0), 0)
	assertEq(t, sqr2Mul(0, 5), 0)
	assertEq(t, sqr2Mul(5, 0), 0)
	assertEq(t, sqr2Mul(0, 1024), 0)
	assertEq(t, sqr2Mul(1024, 0), 0)
	assertEq(t, sqr2Mul(2, 6), 96)
	assertEq(t, sqr2Mul(6, 2), 544)
	assertEq(t, sqr2Mul(3, 8), 136)
	assertEq(t, sqr2Mul(8, 3), 4123)
	assertEq(t, sqr2Mul(125, 19), 3075)
	assertEq(t, sqr2Mul(19, 125), 590)
	assertEq(t, sqr2Mul(125, 37), 5123)
	assertEq(t, sqr2Mul(37, 125), 854)
	assertEq(t, sqr2Mul(4095, 1), 2883)
	assertEq(t, sqr2Mul(1, 4095), 4095)
	assertEq(t, sqr2Mul(8191, 1), 5190)
	assertEq(t, sqr2Mul(1, 8191), 8191)
}

func testSqrMul(t *testing.T, sqrMul tsqrmul) {
	assertEq(t, sqrMul(0, 0), 0)
	assertEq(t, sqrMul(0, 1), 0)
	assertEq(t, sqrMul(1, 0), 0)
	assertEq(t, sqrMul(0, 5), 0)
	assertEq(t, sqrMul(5, 0), 0)
	assertEq(t, sqrMul(0, 1024), 0)
	assertEq(t, sqrMul(1024, 0), 0)
	assertEq(t, sqrMul(2, 6), 24)
	assertEq(t, sqrMul(6, 2), 40)
	assertEq(t, sqrMul(3, 8), 40)
	assertEq(t, sqrMul(8, 3), 192)
	assertEq(t, sqrMul(125, 19), 2582)
	assertEq(t, sqrMul(19, 125), 7332)
	assertEq(t, sqrMul(125, 37), 3012)
	assertEq(t, sqrMul(37, 125), 4916)
	assertEq(t, sqrMul(4095, 1), 3392)
	assertEq(t, sqrMul(1, 4095), 4095)
	assertEq(t, sqrMul(8191, 1), 5402)
	assertEq(t, sqrMul(1, 8191), 8191)
}

func testDiv(t *testing.T, div tdiv) {
	assertEq(t, div(6733, 1), 6733)
	assertEq(t, div(0, 2), 0)
	assertEq(t, div(4, 2), 2)
	assertEq(t, div(4096, 2), 2048)
	assertEq(t, div(9, 3), 7)
	assertEq(t, div(4591, 5), 4205)
	assertEq(t, div(10, 550), 7759)
	assertEq(t, div(3, 5501), 1770)
}

func testInv(t *testing.T, inv tinv) {
	assertEq(t, inv(0), 0)
	assertEq(t, inv(1), 1)
	assertEq(t, inv(2), 4109)
	assertEq(t, inv(3), 8182)
	assertEq(t, inv(4), 6155)
	assertEq(t, inv(4095), 4657)
	assertEq(t, inv(4096), 911)
	assertEq(t, inv(8191), 5953)
}

func testSqr2(t *testing.T, sqr2 tsqr2) {
	assertEq(t, sqr2(0), 0)
	assertEq(t, sqr2(1), 1)
	assertEq(t, sqr2(2), 16)
	assertEq(t, sqr2(3), 17)
	assertEq(t, sqr2(4), 256)
	assertEq(t, sqr2(4095), 2883)
	assertEq(t, sqr2(4096), 7941)
	assertEq(t, sqr2(8191), 5190)
}

func testMul(t *testing.T, mul tmul) {
	assertEq(t, mul(0, 0), 0)
	assertEq(t, mul(0, 1), 0)
	assertEq(t, mul(1, 0), 0)
	assertEq(t, mul(0, 5), 0)
	assertEq(t, mul(5, 0), 0)
	assertEq(t, mul(0, 1024), 0)
	assertEq(t, mul(1024, 0), 0)
	assertEq(t, mul(2, 6), 12)
	assertEq(t, mul(6, 2), 12)
	assertEq(t, mul(3, 8), 24)
	assertEq(t, mul(8, 3), 24)
	assertEq(t, mul(125, 19), 1879)
	assertEq(t, mul(19, 125), 1879)
	assertEq(t, mul(125, 37), 3625)
	assertEq(t, mul(37, 125), 3625)
	assertEq(t, mul(4095, 1), 4095)
	assertEq(t, mul(1, 4095), 4095)
	assertEq(t, mul(8191, 1), 8191)
	assertEq(t, mul(1, 8191), 8191)
}

func testAdd(t *testing.T, add tadd) {
	assertEq(t, add(0x0000, 0x0000), 0x0000)
	assertEq(t, add(0x0000, 0x0001), 0x0001)
	assertEq(t, add(0x0001, 0x0000), 0x0001)
	assertEq(t, add(0x0001, 0x0001), 0x0000)
	assertEq(t, add(0x000F, 0x0000), 0x000F)
	assertEq(t, add(0x000F, 0x0001), 0x000E)
	assertEq(t, add(0x00FF, 0x0100), 0x01FF)
	assertEq(t, add(0xF0F0, 0x0F0F), 0xFFFF)
}
