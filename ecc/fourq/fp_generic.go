// +build go1.12

package fourq

import (
	"math/bits"
	"unsafe"
)

type elt64 = [2]uint64

const mask = uint64(1) << 63

func fpModGeneric(c *Fp) { fpSubGeneric(c, c, &modulusP) }

func fpAddGeneric(c, a, b *Fp) {
	aa, bb, cc := (*elt64)(unsafe.Pointer(a)), (*elt64)(unsafe.Pointer(b)), (*elt64)(unsafe.Pointer(c))
	c0, x := bits.Add64(aa[0], bb[0], 0)
	c1, _ := bits.Add64(aa[1], bb[1], x)
	bit := (c1 >> 63) & 1
	c1 = c1 &^ mask
	cc[0], x = bits.Add64(c0, 0, bit)
	cc[1], _ = bits.Add64(c1, 0, x)
}

func fpSubGeneric(c, a, b *Fp) {
	aa, bb, cc := (*elt64)(unsafe.Pointer(a)), (*elt64)(unsafe.Pointer(b)), (*elt64)(unsafe.Pointer(c))
	c0, x := bits.Sub64(aa[0], bb[0], 0)
	c1, _ := bits.Sub64(aa[1], bb[1], x)
	x = (c1 & mask) >> 63
	c1 = c1 &^ mask
	cc[0], x = bits.Sub64(c0, 0, x)
	cc[1], _ = bits.Sub64(c1, 0, x)
}

func fpMulGeneric(c, a, b *Fp) {
	aa, bb, cc := (*elt64)(unsafe.Pointer(a)), (*elt64)(unsafe.Pointer(b)), (*elt64)(unsafe.Pointer(c))
	c1, c0 := bits.Mul64(aa[0], bb[0])
	hi, lo := bits.Mul64(aa[0], bb[1])
	c0, x := bits.Add64(c0, hi<<1, 0)
	c1, c2 := bits.Add64(c1, lo, x)

	hi, lo = bits.Mul64(aa[1], bb[0])
	c0, x = bits.Add64(c0, hi<<1, 0)
	c1, x = bits.Add64(c1, lo, x)
	c2, _ = bits.Add64(c2, 0, x)

	hi, lo = bits.Mul64(aa[1], bb[1])
	hi = (hi << 1) | (lo >> 63)
	lo = lo << 1
	c0, x = bits.Add64(c0, lo, 0)
	c1, x = bits.Add64(c1, hi, x)
	c2, _ = bits.Add64(c2, 0, x)

	c2 = c2 << 1
	x = (c1 & mask) >> 63
	c1 = c1 &^ mask
	c0, x = bits.Add64(c0, c2, x)
	c1, _ = bits.Add64(c1, 0, x)

	x = (c1 & mask) >> 63
	c1 = c1 &^ mask
	cc[0], x = bits.Add64(c0, 0, x)
	cc[1], _ = bits.Add64(c1, 0, x)
}

func fpSqrGeneric(c, a *Fp) { fpMulGeneric(c, a, a) }

func fpHlfGeneric(c, a *Fp) {
	aa, cc := (*elt64)(unsafe.Pointer(a)), (*elt64)(unsafe.Pointer(c))
	hlf := aa[0] & 0x1
	cc[0] = (aa[1] << 63) | (aa[0] >> 1)
	cc[1] = (hlf << 62) | (aa[1] >> 1)
}
