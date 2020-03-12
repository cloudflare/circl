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
	c1, x = bits.Add64(c1, c1, 0)
	cc[0], x = bits.Add64(c0, 0, x)
	cc[1], _ = bits.Add64(c1>>1, 0, x)
}

func fpSubGeneric(c, a, b *Fp) {
	aa, bb, cc := (*elt64)(unsafe.Pointer(a)), (*elt64)(unsafe.Pointer(b)), (*elt64)(unsafe.Pointer(c))
	c0, x := bits.Sub64(aa[0], bb[0], 0)
	c1, _ := bits.Sub64(aa[1], bb[1], x)
	c1, x = bits.Add64(c1, c1, 0)
	cc[0], x = bits.Sub64(c0, 0, x)
	cc[1], _ = bits.Sub64(c1>>1, 0, x)
}

func fpMulGeneric(c, a, b *Fp) {
	aa, bb, cc := (*elt64)(unsafe.Pointer(a)), (*elt64)(unsafe.Pointer(b)), (*elt64)(unsafe.Pointer(c))
	c1, c0 := bits.Mul64(aa[0], bb[0])
	hi, lo := bits.Mul64(aa[0], bb[1])
	c0, x := bits.Add64(c0, hi<<1, 0)
	c1, x = bits.Add64(c1, lo, x)
	c2, _ := bits.Add64(0, 0, x)

	hi, lo = bits.Mul64(aa[1], bb[0])
	c0, x = bits.Add64(c0, hi<<1, 0)
	c1, x = bits.Add64(c1, lo, x)
	c2, _ = bits.Add64(c2, 0, x)

	hi, lo = bits.Mul64(aa[1], bb[1])
	lo, x = bits.Add64(lo, lo, 0)
	hi, _ = bits.Add64(hi, hi, x)

	c0, x = bits.Add64(c0, lo, 0)
	c1, x = bits.Add64(c1, hi, x)
	c2, _ = bits.Add64(c2, 0, x)

	c1, x = bits.Add64(c1, c1, 0)
	c0, x = bits.Add64(c0, c2<<1, x)
	c1, _ = bits.Add64(c1>>1, 0, x)

	c1, x = bits.Add64(c1, c1, 0)
	cc[0], x = bits.Add64(c0, 0, x)
	cc[1], _ = bits.Add64(c1>>1, 0, x)
}

func fpSqrGeneric(c, a *Fp) { fpMulGeneric(c, a, a) }

func fpHlfGeneric(c, a *Fp) {
	aa, cc := (*elt64)(unsafe.Pointer(a)), (*elt64)(unsafe.Pointer(c))
	hlf := aa[0] & 0x1
	cc[0] = (aa[1] << 63) | (aa[0] >> 1)
	cc[1] = (hlf << 62) | (aa[1] >> 1)
}
