// Package gf2e13 provides finite field arithmetic over GF(2^13).
package gf2e13

// Elt is a field element of characteristic 2 modulo z^13 + z^4 + z^3 + z + 1
type Elt = uint16

const (
	Bits = 13
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
	t := tmp & 0x1FF0000
	tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13)

	t = tmp & 0x000E000
	tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13)

	return uint16(tmp & Mask)
}

// sqr2 calculates a^4
func sqr2(a Elt) Elt {
	a64 := uint64(a)
	a64 = (a64 | (a64 << 24)) & 0x000000FF000000FF
	a64 = (a64 | (a64 << 12)) & 0x000F000F000F000F
	a64 = (a64 | (a64 << 6)) & 0x0303030303030303
	a64 = (a64 | (a64 << 3)) & 0x1111111111111111

	t := a64 & 0x0001FF0000000000
	a64 ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13)
	t = a64 & 0x000000FF80000000
	a64 ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13)
	t = a64 & 0x000000007FC00000
	a64 ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13)
	t = a64 & 0x00000000003FE000
	a64 ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13)

	return uint16(a64 & Mask)
}

// sqrMul calculates the product of a^2 and b
func sqrMul(a, b Elt) Elt {
	a64 := uint64(a)
	b64 := uint64(b)

	x := (b64 << 6) * (a64 & (1 << 6))
	a64 ^= a64 << 7
	x ^= b64 * (a64 & (0x04001))
	x ^= (b64 * (a64 & (0x08002))) << 1
	x ^= (b64 * (a64 & (0x10004))) << 2
	x ^= (b64 * (a64 & (0x20008))) << 3
	x ^= (b64 * (a64 & (0x40010))) << 4
	x ^= (b64 * (a64 & (0x80020))) << 5

	t := x & 0x0000001FF0000000
	x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13)
	t = x & 0x000000000FF80000
	x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13)
	t = x & 0x000000000007E000
	x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13)

	return uint16(x & Mask)
}

// sqr2Mul calculates the product of a^4 and b
func sqr2Mul(a, b Elt) Elt {
	a64 := uint64(a)
	b64 := uint64(b)

	x := (b64 << 18) * (a64 & (1 << 6))
	a64 ^= a64 << 21
	x ^= b64 * (a64 & (0x010000001))
	x ^= (b64 * (a64 & (0x020000002))) << 3
	x ^= (b64 * (a64 & (0x040000004))) << 6
	x ^= (b64 * (a64 & (0x080000008))) << 9
	x ^= (b64 * (a64 & (0x100000010))) << 12
	x ^= (b64 * (a64 & (0x200000020))) << 15

	t := x & 0x1FF0000000000000
	x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13)
	t = x & 0x000FF80000000000
	x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13)
	t = x & 0x000007FC00000000
	x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13)
	t = x & 0x00000003FE000000
	x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13)
	t = x & 0x0000000001FE0000
	x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13)
	t = x & 0x000000000001E000
	x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13)

	return uint16(x & Mask)
}

// Inv calculates the multiplicative inverse of Elt element a
func Inv(a Elt) Elt {
	return Div(1, a)
}

// Div calculates a / b
func Div(a, b Elt) Elt {
	tmp3 := sqrMul(b, b)         // b^3
	tmp15 := sqr2Mul(tmp3, tmp3) // b^15 = b^(3*2*2+3)
	out := sqr2(tmp15)
	out = sqr2Mul(out, tmp15) // b^255 = b^(15*4*4+15)
	out = sqr2(out)
	out = sqr2Mul(out, tmp15) // b^4095 = b^(255*2*2*2*2+15)

	return sqrMul(out, a) // b^8190 = b^(4095*2) = b^-1
}
