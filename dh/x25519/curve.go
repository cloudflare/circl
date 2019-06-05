package x25519

import (
	fp255 "github.com/cloudflare/circl/math/fp25519"
)

type curve struct{}

var c255 curve

// ladderJoye calculates a fixed-point multiplication with the generator point.
// The algorithm is the right-to-left Joye's ladder as described
// in "How to precompute a ladder" in SAC'2017.
func (c *curve) ladderJoye(k *Key) {
	w := [5]fp255.Elt{} // [mu,x1,z1,x2,z2] order must be preserved.
	fp255.SetOne(&w[1]) // x1 = 1
	fp255.SetOne(&w[2]) // z1 = 1
	w[3] = fp255.Elt{   // x2 = G-S
		0xbd, 0xaa, 0x2f, 0xc8, 0xfe, 0xe1, 0x94, 0x7e,
		0xf8, 0xed, 0xb2, 0x14, 0xae, 0x95, 0xf0, 0xbb,
		0xe2, 0x48, 0x5d, 0x23, 0xb9, 0xa0, 0xc7, 0xad,
		0x34, 0xab, 0x7c, 0xe2, 0xee, 0xcd, 0xae, 0x1e,
	}
	fp255.SetOne(&w[4]) // z2 = 1

	const n = 255
	const h = 3
	swap := uint(1)
	for s := 0; s < n-h; s++ {
		i := (s + h) / 8
		j := (s + h) % 8
		bit := uint((k[i] >> uint(j)) & 1)
		copy(w[0][:], tableGenerator[s*Size:(s+1)*Size])
		c.difAdd(&w, swap^bit)
		swap = bit
	}
	for s := 0; s < h; s++ {
		c.double(&w[1], &w[2])
	}
	c.toAffine((*[fp255.Size]byte)(k), &w[1], &w[2])
}

// ladderMontgomery calculates a generic scalar point multiplication
// The algorithm implemented is the left-to-right Montgomery's ladder.
func (c *curve) ladderMontgomery(k, xP *Key) {
	w := [5]fp255.Elt{}      // [x1, x2, z2, x3, z3] order must be preserved.
	w[0] = *(*fp255.Elt)(xP) // x1 = xP
	fp255.SetOne(&w[1])      // x2 = 1
	w[3] = *(*fp255.Elt)(xP) // x3 = xP
	fp255.SetOne(&w[4])      // z3 = 1

	move := uint(0)
	for s := 255 - 1; s >= 0; s-- {
		i := s / 8
		j := s % 8
		bit := uint((k[i] >> uint(j)) & 1)
		c.ladderStep(&w, move^bit)
		move = bit
	}
	c.toAffine((*[fp255.Size]byte)(k), &w[1], &w[2])
}

func (c *curve) toAffine(k *[fp255.Size]byte, x, z *fp255.Elt) {
	fp255.Inv(z, z)
	fp255.Mul(x, x, z)
	fp255.ToBytes(k[:], x)
}
