// Package gf4096 provides finite field arithmetic over GF(2^12).
package gf4096

// Gf is a field element of characteristic 2 modulo z^12 + z^3 + 1
type Gf = uint16

const (
	GfBits = 12
	GfMask = (1 << GfBits) - 1
)

// Add two Gf elements together. Since an addition in Gf(2) is the same as XOR,
// this implementation uses a simple XOR for addition.
func Add(a, b Gf) Gf {
	return a ^ b
}

// Mul calculate the product of two Gf elements.
func Mul(a, b Gf) Gf {
	// carry-less multiplication by adding "holes"
	// see https://www.bearssl.org/constanttime.html#ghash-for-gcm
	x := uint64(a)
	y := uint64(b)
	x0 := x & 0x111111111111
	x1 := x & 0x222222222222
	x2 := x & 0x444444444444
	x3 := x & 0x888888888888
	y0 := y & 0x111111111111
	y1 := y & 0x222222222222
	y2 := y & 0x444444444444
	y3 := y & 0x888888888888
	z0 := (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)
	z1 := (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)
	z2 := (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)
	z3 := (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)
	z0 &= 0x111111111111
	z1 &= 0x222222222222
	z2 &= 0x444444444444
	z3 &= 0x888888888888
	tmp := z0 | z1 | z2 | z3

	// polynomial reduction
	t := tmp & 0x7FC000
	tmp ^= t >> 9
	tmp ^= t >> 12

	t = tmp & 0x3000
	tmp ^= t >> 9
	tmp ^= t >> 12

	return uint16(tmp & GfMask)
}

// sqr calculates the square of Gf element a
func sqr(a Gf) Gf {
	a32 := uint32(a)
	a32 = (a32 | (a32 << 8)) & 0x00FF00FF
	a32 = (a32 | (a32 << 4)) & 0x0F0F0F0F
	a32 = (a32 | (a32 << 2)) & 0x33333333
	a32 = (a32 | (a32 << 1)) & 0x55555555

	t := a32 & 0x7FC000
	a32 ^= t >> 9
	a32 ^= t >> 12

	t = a32 & 0x3000
	a32 ^= t >> 9
	a32 ^= t >> 12

	return uint16(a32 & GfMask)
}

// Inv calculates the multiplicative inverse of Gf element a
func Inv(a Gf) Gf {
	out := sqr(a)
	tmp3 := Mul(out, a) // a^3

	out = sqr(sqr(tmp3))
	tmp15 := Mul(out, tmp3) // a^15 = a^(3*2*2 + 3)

	out = sqr(sqr(sqr(sqr(tmp15))))
	out = Mul(out, tmp15) // a^255 = a^(15*2*2*2*2 + 15)

	out = sqr(sqr(out))
	out = Mul(out, tmp3) // a^1023 = a^(255*2*2 + 3)

	out = Mul(sqr(out), a) // a^2047 = a^(1023*2 + 1)
	return sqr(out)        // a^4094 = a^(2047 * 2)
}

// Div calculates a / b
func Div(a, b Gf) Gf {
	return Mul(Inv(b), a)
}
