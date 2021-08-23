//go:build go1.12
// +build go1.12

package fourq

import (
	"encoding/binary"
	"math/bits"
)

func fpModGeneric(c *Fp) { fpSubGeneric(c, c, &modulusP) }

func fpAddGeneric(c, a, b *Fp) {
	a0 := binary.LittleEndian.Uint64(a[0*8 : 1*8])
	a1 := binary.LittleEndian.Uint64(a[1*8 : 2*8])

	b0 := binary.LittleEndian.Uint64(b[0*8 : 1*8])
	b1 := binary.LittleEndian.Uint64(b[1*8 : 2*8])

	c0, x := bits.Add64(a0, b0, 0)
	c1, _ := bits.Add64(a1, b1, x)
	c1, x = bits.Add64(c1, c1, 0)
	c0, x = bits.Add64(c0, 0, x)
	c1, _ = bits.Add64(c1>>1, 0, x)

	binary.LittleEndian.PutUint64(c[0*8:1*8], c0)
	binary.LittleEndian.PutUint64(c[1*8:2*8], c1)
}

func fpSubGeneric(c, a, b *Fp) {
	a0 := binary.LittleEndian.Uint64(a[0*8 : 1*8])
	a1 := binary.LittleEndian.Uint64(a[1*8 : 2*8])

	b0 := binary.LittleEndian.Uint64(b[0*8 : 1*8])
	b1 := binary.LittleEndian.Uint64(b[1*8 : 2*8])

	c0, x := bits.Sub64(a0, b0, 0)
	c1, _ := bits.Sub64(a1, b1, x)
	c1, x = bits.Add64(c1, c1, 0)
	c0, x = bits.Sub64(c0, 0, x)
	c1, _ = bits.Sub64(c1>>1, 0, x)

	binary.LittleEndian.PutUint64(c[0*8:1*8], c0)
	binary.LittleEndian.PutUint64(c[1*8:2*8], c1)
}

func fpMulGeneric(c, a, b *Fp) {
	a0 := binary.LittleEndian.Uint64(a[0*8 : 1*8])
	a1 := binary.LittleEndian.Uint64(a[1*8 : 2*8])

	b0 := binary.LittleEndian.Uint64(b[0*8 : 1*8])
	b1 := binary.LittleEndian.Uint64(b[1*8 : 2*8])

	c1, c0 := bits.Mul64(a0, b0)
	hi, lo := bits.Mul64(a0, b1)
	c0, x := bits.Add64(c0, hi<<1, 0)
	c1, x = bits.Add64(c1, lo, x)
	c2, _ := bits.Add64(0, 0, x)

	hi, lo = bits.Mul64(a1, b0)
	c0, x = bits.Add64(c0, hi<<1, 0)
	c1, x = bits.Add64(c1, lo, x)
	c2, _ = bits.Add64(c2, 0, x)

	hi, lo = bits.Mul64(a1, b1)
	lo, x = bits.Add64(lo, lo, 0)
	hi, _ = bits.Add64(hi, hi, x)

	c0, x = bits.Add64(c0, lo, 0)
	c1, x = bits.Add64(c1, hi, x)
	c2, _ = bits.Add64(c2, 0, x)

	c1, x = bits.Add64(c1, c1, 0)
	c0, x = bits.Add64(c0, c2<<1, x)
	c1, _ = bits.Add64(c1>>1, 0, x)

	c1, x = bits.Add64(c1, c1, 0)
	c0, x = bits.Add64(c0, 0, x)
	c1, _ = bits.Add64(c1>>1, 0, x)

	binary.LittleEndian.PutUint64(c[0*8:1*8], c0)
	binary.LittleEndian.PutUint64(c[1*8:2*8], c1)
}

func fpSqrGeneric(c, a *Fp) { fpMulGeneric(c, a, a) }

func fpHlfGeneric(c, a *Fp) {
	a0 := binary.LittleEndian.Uint64(a[0*8 : 1*8])
	a1 := binary.LittleEndian.Uint64(a[1*8 : 2*8])

	hlf := a0 & 0x1
	c0 := (a1 << 63) | (a0 >> 1)
	c1 := (hlf << 62) | (a1 >> 1)

	binary.LittleEndian.PutUint64(c[0*8:1*8], c0)
	binary.LittleEndian.PutUint64(c[1*8:2*8], c1)
}
