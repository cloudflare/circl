// +build !amd64

package fp448

import (
	"math/bits"
	"unsafe"
)

type elt64 [7]uint64

// Cmov assigns y to x if n is 1.
func Cmov(x, y *Elt, n uint) {
	cmov64((*elt64)(unsafe.Pointer(x)), (*elt64)(unsafe.Pointer(y)), n)
}

// Cswap interchages x and y if n is 1.
func Cswap(x, y *Elt, n uint) {
	cswap64((*elt64)(unsafe.Pointer(x)), (*elt64)(unsafe.Pointer(y)), n)
}

// Add calculates z = x+y mod p
func Add(z, x, y *Elt) {
	add64((*elt64)(unsafe.Pointer(z)),
		(*elt64)(unsafe.Pointer(x)), (*elt64)(unsafe.Pointer(y)))
}

// Sub calculates z = x-y mod p
func Sub(z, x, y *Elt) {
	sub64((*elt64)(unsafe.Pointer(z)),
		(*elt64)(unsafe.Pointer(x)), (*elt64)(unsafe.Pointer(y)))
}

// AddSub calculates (x,y) = (x+y mod p, x-y mod p)
func AddSub(x, y *Elt) {
	x64 := (*elt64)(unsafe.Pointer(x))
	y64 := (*elt64)(unsafe.Pointer(y))
	z64 := &elt64{}
	add64(z64, x64, y64)
	sub64(y64, x64, y64)
	*x64 = *z64
}

// Mul calculates z = x*y mod p
func Mul(z, x, y *Elt) {
	mul64((*elt64)(unsafe.Pointer(z)),
		(*elt64)(unsafe.Pointer(x)), (*elt64)(unsafe.Pointer(y)))
}

// Sqr calculates z = x^2 mod p
func Sqr(z, x *Elt) {
	sqr64((*elt64)(unsafe.Pointer(z)), (*elt64)(unsafe.Pointer(x)))
}

func cmov64(x, y *elt64, n uint) {
	m := -uint64(n & 0x1)
	for i := range x {
		x[i] = (x[i] &^ m) | (y[i] & m)
	}
}

func cswap64(x, y *elt64, n uint) {
	m := -uint64(n & 0x1)
	for i := range x {
		t := m & (x[i] ^ y[i])
		x[i] ^= t
		y[i] ^= t
	}
}

func add64(z, x, y *elt64) {
	z0, c0 := bits.Add64(x[0], y[0], 0)
	z1, c1 := bits.Add64(x[1], y[1], c0)
	z2, c2 := bits.Add64(x[2], y[2], c1)
	z3, c3 := bits.Add64(x[3], y[3], c2)
	z4, c4 := bits.Add64(x[4], y[4], c3)
	z5, c5 := bits.Add64(x[5], y[5], c4)
	z6, z7 := bits.Add64(x[6], y[6], c5)

	z0, c0 = bits.Add64(z0, z7, 0)
	z1, c1 = bits.Add64(z1, 0, c0)
	z2, c2 = bits.Add64(z2, 0, c1)
	z3, c3 = bits.Add64(z3, z7<<32, c2)
	z4, c4 = bits.Add64(z4, 0, c3)
	z5, c5 = bits.Add64(z5, 0, c4)
	z6, z7 = bits.Add64(z6, 0, c5)

	z[0], c0 = bits.Add64(z0, z7, 0)
	z[1], c1 = bits.Add64(z1, 0, c0)
	z[2], c2 = bits.Add64(z2, 0, c1)
	z[3], c3 = bits.Add64(z3, z7<<32, c2)
	z[4], c4 = bits.Add64(z4, 0, c3)
	z[5], c5 = bits.Add64(z5, 0, c4)
	z[6], _ = bits.Add64(z6, 0, c5)
}

func sub64(z, x, y *elt64) {
	z0, c0 := bits.Sub64(x[0], y[0], 0)
	z1, c1 := bits.Sub64(x[1], y[1], c0)
	z2, c2 := bits.Sub64(x[2], y[2], c1)
	z3, c3 := bits.Sub64(x[3], y[3], c2)
	z4, c4 := bits.Sub64(x[4], y[4], c3)
	z5, c5 := bits.Sub64(x[5], y[5], c4)
	z6, z7 := bits.Sub64(x[6], y[6], c5)

	z0, c0 = bits.Sub64(z0, z7, 0)
	z1, c1 = bits.Sub64(z1, 0, c0)
	z2, c2 = bits.Sub64(z2, 0, c1)
	z3, c3 = bits.Sub64(z3, z7<<32, c2)
	z4, c4 = bits.Sub64(z4, 0, c3)
	z5, c5 = bits.Sub64(z5, 0, c4)
	z6, z7 = bits.Sub64(z6, 0, c5)

	z[0], c0 = bits.Sub64(z0, z7, 0)
	z[1], c1 = bits.Sub64(z1, 0, c0)
	z[2], c2 = bits.Sub64(z2, 0, c1)
	z[3], c3 = bits.Sub64(z3, z7<<32, c2)
	z[4], c4 = bits.Sub64(z4, 0, c3)
	z[5], c5 = bits.Sub64(z5, 0, c4)
	z[6], _ = bits.Sub64(z6, 0, c5)
}

func mul64(z, x, y *elt64) {
	x0, x1, x2, x3, x4, x5, x6 := x[0], x[1], x[2], x[3], x[4], x[5], x[6]
	yi := y[0]
	h0, l0 := bits.Mul64(x0, yi)
	h1, l1 := bits.Mul64(x1, yi)
	h2, l2 := bits.Mul64(x2, yi)
	h3, l3 := bits.Mul64(x3, yi)
	h4, l4 := bits.Mul64(x4, yi)
	h5, l5 := bits.Mul64(x5, yi)
	h6, l6 := bits.Mul64(x6, yi)

	z[0] = l0
	a0, c0 := bits.Add64(h0, l1, 0)
	a1, c1 := bits.Add64(h1, l2, c0)
	a2, c2 := bits.Add64(h2, l3, c1)
	a3, c3 := bits.Add64(h3, l4, c2)
	a4, c4 := bits.Add64(h4, l5, c3)
	a5, c5 := bits.Add64(h5, l6, c4)
	a6, _ := bits.Add64(h6, 0, c5)

	for i := 1; i < 7; i++ {
		yi = y[i]
		h0, l0 = bits.Mul64(x0, yi)
		h1, l1 = bits.Mul64(x1, yi)
		h2, l2 = bits.Mul64(x2, yi)
		h3, l3 = bits.Mul64(x3, yi)
		h4, l4 = bits.Mul64(x4, yi)
		h5, l5 = bits.Mul64(x5, yi)
		h6, l6 = bits.Mul64(x6, yi)

		z[i], c0 = bits.Add64(a0, l0, 0)
		a0, c1 = bits.Add64(a1, l1, c0)
		a1, c2 = bits.Add64(a2, l2, c1)
		a2, c3 = bits.Add64(a3, l3, c2)
		a3, c4 = bits.Add64(a4, l4, c3)
		a4, c5 = bits.Add64(a5, l5, c4)
		a5, a6 = bits.Add64(a6, l6, c5)

		a0, c0 = bits.Add64(a0, h0, 0)
		a1, c1 = bits.Add64(a1, h1, c0)
		a2, c2 = bits.Add64(a2, h2, c1)
		a3, c3 = bits.Add64(a3, h3, c2)
		a4, c4 = bits.Add64(a4, h4, c3)
		a5, c5 = bits.Add64(a5, h5, c4)
		a6, _ = bits.Add64(a6, h6, c5)
	}
	red64(z, &elt64{a0, a1, a2, a3, a4, a5, a6})
}

func sqr64(z, x *elt64) { mul64(z, x, x) }

func red64(z, h *elt64) {
	/* (2C13, 2C12, 2C11, 2C10|C10, C9, C8, C7) + (C6,...,C0) */
	h0 := h[0]
	h1 := h[1]
	h2 := h[2]
	h3 := ((h[3] & (0xFFFFFFFF << 32)) << 1) | (h[3] & 0xFFFFFFFF)
	h4 := (h[3] >> 63) | (h[4] << 1)
	h5 := (h[4] >> 63) | (h[5] << 1)
	h6 := (h[5] >> 63) | (h[6] << 1)
	h7 := (h[6] >> 63)

	l0, c0 := bits.Add64(h0, z[0], 0)
	l1, c1 := bits.Add64(h1, z[1], c0)
	l2, c2 := bits.Add64(h2, z[2], c1)
	l3, c3 := bits.Add64(h3, z[3], c2)
	l4, c4 := bits.Add64(h4, z[4], c3)
	l5, c5 := bits.Add64(h5, z[5], c4)
	l6, c6 := bits.Add64(h6, z[6], c5)
	l7, _ := bits.Add64(h7, 0, c6)

	/* (C10C9, C9C8,C8C7,C7C13,C13C12,C12C11,C11C10) + (C6,...,C0) */
	h0 = (h[3] >> 32) | (h[4] << 32)
	h1 = (h[4] >> 32) | (h[5] << 32)
	h2 = (h[5] >> 32) | (h[6] << 32)
	h3 = (h[6] >> 32) | (h[0] << 32)
	h4 = (h[0] >> 32) | (h[1] << 32)
	h5 = (h[1] >> 32) | (h[2] << 32)
	h6 = (h[2] >> 32) | (h[3] << 32)

	l0, c0 = bits.Add64(l0, h0, 0)
	l1, c1 = bits.Add64(l1, h1, c0)
	l2, c2 = bits.Add64(l2, h2, c1)
	l3, c3 = bits.Add64(l3, h3, c2)
	l4, c4 = bits.Add64(l4, h4, c3)
	l5, c5 = bits.Add64(l5, h5, c4)
	l6, c6 = bits.Add64(l6, h6, c5)
	l7, _ = bits.Add64(l7, 0, c6)

	/* (C7 MOD P) + (C6,...,C0) */
	z[0], c0 = bits.Add64(l0, l7, 0)
	z[1], c1 = bits.Add64(l1, 0, c0)
	z[2], c2 = bits.Add64(l2, 0, c1)
	z[3], c3 = bits.Add64(l3, l7<<32, c2)
	z[4], c4 = bits.Add64(l4, 0, c3)
	z[5], c5 = bits.Add64(l5, 0, c4)
	z[6], l7 = bits.Add64(l6, 0, c5)

	z[0] += l7
	z[3] += l7 << 32
}
