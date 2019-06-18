package fp448

import (
	"math/bits"
	"unsafe"
)

type elt64 [7]uint64

func cmovGeneric(x, y *Elt, n uint) {
	xx, yy := (*elt64)(unsafe.Pointer(x)), (*elt64)(unsafe.Pointer(y))
	m := -uint64(n & 0x1)
	for i := range xx {
		xx[i] = (xx[i] &^ m) | (yy[i] & m)
	}
}

func cswapGeneric(x, y *Elt, n uint) {
	xx, yy := (*elt64)(unsafe.Pointer(x)), (*elt64)(unsafe.Pointer(y))
	m := -uint64(n & 0x1)
	for i := range xx {
		t := m & (xx[i] ^ yy[i])
		xx[i] ^= t
		yy[i] ^= t
	}
}

func addGeneric(z, x, y *Elt) {
	xx := (*elt64)(unsafe.Pointer(x))
	yy := (*elt64)(unsafe.Pointer(y))
	zz := (*elt64)(unsafe.Pointer(z))

	z0, c0 := bits.Add64(xx[0], yy[0], 0)
	z1, c1 := bits.Add64(xx[1], yy[1], c0)
	z2, c2 := bits.Add64(xx[2], yy[2], c1)
	z3, c3 := bits.Add64(xx[3], yy[3], c2)
	z4, c4 := bits.Add64(xx[4], yy[4], c3)
	z5, c5 := bits.Add64(xx[5], yy[5], c4)
	z6, z7 := bits.Add64(xx[6], yy[6], c5)

	z0, c0 = bits.Add64(z0, z7, 0)
	z1, c1 = bits.Add64(z1, 0, c0)
	z2, c2 = bits.Add64(z2, 0, c1)
	z3, c3 = bits.Add64(z3, z7<<32, c2)
	z4, c4 = bits.Add64(z4, 0, c3)
	z5, c5 = bits.Add64(z5, 0, c4)
	z6, z7 = bits.Add64(z6, 0, c5)

	zz[0], c0 = bits.Add64(z0, z7, 0)
	zz[1], c1 = bits.Add64(z1, 0, c0)
	zz[2], c2 = bits.Add64(z2, 0, c1)
	zz[3], c3 = bits.Add64(z3, z7<<32, c2)
	zz[4], c4 = bits.Add64(z4, 0, c3)
	zz[5], c5 = bits.Add64(z5, 0, c4)
	zz[6], _ = bits.Add64(z6, 0, c5)
}

func subGeneric(z, x, y *Elt) {
	xx := (*elt64)(unsafe.Pointer(x))
	yy := (*elt64)(unsafe.Pointer(y))
	zz := (*elt64)(unsafe.Pointer(z))
	z0, c0 := bits.Sub64(xx[0], yy[0], 0)
	z1, c1 := bits.Sub64(xx[1], yy[1], c0)
	z2, c2 := bits.Sub64(xx[2], yy[2], c1)
	z3, c3 := bits.Sub64(xx[3], yy[3], c2)
	z4, c4 := bits.Sub64(xx[4], yy[4], c3)
	z5, c5 := bits.Sub64(xx[5], yy[5], c4)
	z6, z7 := bits.Sub64(xx[6], yy[6], c5)

	z0, c0 = bits.Sub64(z0, z7, 0)
	z1, c1 = bits.Sub64(z1, 0, c0)
	z2, c2 = bits.Sub64(z2, 0, c1)
	z3, c3 = bits.Sub64(z3, z7<<32, c2)
	z4, c4 = bits.Sub64(z4, 0, c3)
	z5, c5 = bits.Sub64(z5, 0, c4)
	z6, z7 = bits.Sub64(z6, 0, c5)

	zz[0], c0 = bits.Sub64(z0, z7, 0)
	zz[1], c1 = bits.Sub64(z1, 0, c0)
	zz[2], c2 = bits.Sub64(z2, 0, c1)
	zz[3], c3 = bits.Sub64(z3, z7<<32, c2)
	zz[4], c4 = bits.Sub64(z4, 0, c3)
	zz[5], c5 = bits.Sub64(z5, 0, c4)
	zz[6], _ = bits.Sub64(z6, 0, c5)
}

func addsubGeneric(x, y *Elt) {
	z := &Elt{}
	addGeneric(z, x, y)
	subGeneric(y, x, y)
	*x = *z
}

func mulGeneric(z, x, y *Elt) {
	xx := (*elt64)(unsafe.Pointer(x))
	yy := (*elt64)(unsafe.Pointer(y))
	zz := (*elt64)(unsafe.Pointer(z))

	x0, x1, x2, x3, x4, x5, x6 := xx[0], xx[1], xx[2], xx[3], xx[4], xx[5], xx[6]
	yi := yy[0]
	h0, l0 := bits.Mul64(x0, yi)
	h1, l1 := bits.Mul64(x1, yi)
	h2, l2 := bits.Mul64(x2, yi)
	h3, l3 := bits.Mul64(x3, yi)
	h4, l4 := bits.Mul64(x4, yi)
	h5, l5 := bits.Mul64(x5, yi)
	h6, l6 := bits.Mul64(x6, yi)

	zz[0] = l0
	a0, c0 := bits.Add64(h0, l1, 0)
	a1, c1 := bits.Add64(h1, l2, c0)
	a2, c2 := bits.Add64(h2, l3, c1)
	a3, c3 := bits.Add64(h3, l4, c2)
	a4, c4 := bits.Add64(h4, l5, c3)
	a5, c5 := bits.Add64(h5, l6, c4)
	a6, _ := bits.Add64(h6, 0, c5)

	for i := 1; i < 7; i++ {
		yi = yy[i]
		h0, l0 = bits.Mul64(x0, yi)
		h1, l1 = bits.Mul64(x1, yi)
		h2, l2 = bits.Mul64(x2, yi)
		h3, l3 = bits.Mul64(x3, yi)
		h4, l4 = bits.Mul64(x4, yi)
		h5, l5 = bits.Mul64(x5, yi)
		h6, l6 = bits.Mul64(x6, yi)

		zz[i], c0 = bits.Add64(a0, l0, 0)
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
	red64(zz, &elt64{a0, a1, a2, a3, a4, a5, a6})
}

func sqrGeneric(z, x *Elt) { mulGeneric(z, x, x) }

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
