// Package gf2e12 provides finite field arithmetic over GF(2^12).
package gf2e12

// Elt is a field element of characteristic 2 modulo z^12 + z^3 + 1
type Elt = uint16

const (
	Bits = 12
	Mask = (1 << Bits) - 1
)

// Add two Elt elements together. Since an addition in Elt(2) is the same as XOR,
// this implementation uses a simple XOR for addition.
func Add(a, b Elt) Elt {
	return a ^ b
}

// Mul calculate the product of two Elt elements.
func Mul(a, b Elt) Elt {
	a64 := uint64(a)
	b64 := uint64(b)

	// if the LSB of b is 1, set tmp to a64, and 0 otherwise
	tmp := a64 & -(b64 & 1)

	// check if i-th bit of b64 is set, add a64 shifted by i bits if so
	for i := 1; i < Bits; i++ {
		tmp ^= a64 * (b64 & (1 << i))
	}

	// polynomial reduction
	t := tmp & 0x7FC000
	tmp ^= t >> 9
	tmp ^= t >> 12

	t = tmp & 0x3000
	tmp ^= t >> 9
	tmp ^= t >> 12

	return Elt(tmp & Mask)
}

// sqr calculates the square of Elt element a
func sqr(a Elt) Elt {
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

	return uint16(a32 & Mask)
}

// Inv calculates the multiplicative inverse of Elt element a
func Inv(a Elt) Elt {
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
func Div(a, b Elt) Elt {
	return Mul(Inv(b), a)
}
