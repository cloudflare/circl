package ed448

import (
	"encoding/binary"
	"math/bits"
)

// order is 2^446-0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d,
// which is the number of points in the prime subgroup.
var order = [Size]byte{
	0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
	0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
	0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
	0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
	0x00,
}

// residue446 is 2^446 mod order.
var residue446 = [32]byte{
	0x0d, 0xbb, 0xa7, 0x54, 0x6d, 0x3d, 0x87, 0xdc,
	0xaa, 0x70, 0x3a, 0x72, 0x8d, 0x3d, 0x93, 0xde,
	0x6f, 0xc9, 0x29, 0x51, 0xb6, 0x24, 0xb1, 0x3b,
	0x16, 0xdc, 0x35, 0x83, 0x00, 0x00, 0x00, 0x00,
}

// residue448 is 2^448 mod order.
var residue448 = [32]byte{
	0x34, 0xec, 0x9e, 0x52, 0xb5, 0xf5, 0x1c, 0x72,
	0xab, 0xc2, 0xe9, 0xc8, 0x35, 0xf6, 0x4c, 0x7a,
	0xbf, 0x25, 0xa7, 0x44, 0xd9, 0x92, 0xc4, 0xee,
	0x58, 0x70, 0xd7, 0x0c, 0x02, 0x00, 0x00, 0x00,
}

// invFour is 1/4 mod order.
var invFour = [Size]byte{
	0x3d, 0x11, 0xd6, 0xaa, 0xa4, 0x30, 0xde, 0x48,
	0xd5, 0x63, 0x71, 0xa3, 0x9c, 0x30, 0x5b, 0x08,
	0xa4, 0x8d, 0xb5, 0x6b, 0xd2, 0xb6, 0x13, 0x71,
	0xfa, 0x88, 0x32, 0xdf, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
}

// isLessThan returns true if 0 <= x < y, and assumes that slices have the same length.
func isLessThan(x, y []byte) bool {
	i := len(x) - 1
	for i > 0 && x[i] == y[i] {
		i--
	}
	return x[i] < y[i]
}

func byte2uint(z []uint, x []byte) {
	const n = bits.UintSize / 8
	lx := len(x)
	lz := len(z)
	for i := range z[:lz-1] {
		z[i] = toUint(x[n*i:])
	}
	for i, j := n*(lz-1), uint(0); i < lx; i++ {
		z[lz-1] |= uint(x[i]) << j
		j += 8
	}
}

func uint2byte(z []byte, x []uint) {
	const n = bits.UintSize / 8
	for i := range x {
		toByte(z[n*i:], x[i])
	}
}

func toUint(b []byte) uint {
	const i = bits.UintSize / 64 // 0 or 1
	return uint(binary.LittleEndian.Uint32(b[4*i:]))<<(32*i) |
		uint(binary.LittleEndian.Uint32(b))
}

func toByte(b []byte, v uint) {
	const i = bits.UintSize / 64 // 0 or 1
	binary.LittleEndian.PutUint32(b, uint32(v))
	binary.LittleEndian.PutUint32(b[4*i:], uint32(v>>(32*i)))
}

func add(z, x, y []uint) {
	l, L, zz := len(x), len(y), y
	if l > L {
		l, L, zz = L, l, x
	}
	c := uint(0)
	for i := 0; i < l; i++ {
		z[i], c = bits.Add(x[i], y[i], c)
	}
	for i := l; i < L; i++ {
		z[i], c = bits.Add(zz[i], 0, c)
	}
	z[L] = c
}

func mul(z, x, y []uint) {
	carry := uint(0)
	var c uint
	for j := range y {
		hi, lo := bits.Mul(x[0], y[j])
		z[j], c = bits.Add(lo, carry, 0)
		carry, _ = bits.Add(hi, 0, c)
	}
	z[len(y)] = carry
	lx := len(x)
	for i := 1; i < lx; i++ {
		carry := uint(0)
		for j := range y {
			hi, lo := bits.Mul(x[i], y[j])
			lo, c := bits.Add(lo, z[i+j], 0)
			hi, _ = bits.Add(hi, 0, c)
			z[i+j], c = bits.Add(lo, carry, 0)
			carry, _ = bits.Add(hi, 0, c)
		}
		z[i+len(y)] = carry
	}
}

// calculateS performs s = r+k*a mod Order.
func calculateS(s, r, k, a []byte) {
	const n = (448 + bits.UintSize - 1) / bits.UintSize
	const l = (8*Size + bits.UintSize - 1) / bits.UintSize
	var rr, kk, aa [l]uint
	var cc [2*l + 1]uint
	byte2uint(rr[:], r)
	byte2uint(kk[:], k)
	byte2uint(aa[:], a)
	mul(cc[:], kk[:], aa[:])
	add(cc[:], cc[:2*l], rr[:])
	reduce(cc[:])
	uint2byte(s, cc[:n])
}

// div4 calculates x = x/4 mod order.
func div4(x []byte) {
	const n = (448 + bits.UintSize - 1) / bits.UintSize
	const l = (8*Size + bits.UintSize - 1) / bits.UintSize
	var xx, inv4 [l]uint
	var cc [2 * l]uint
	byte2uint(xx[:], x)
	byte2uint(inv4[:], invFour[:])
	mul(cc[:], xx[:], inv4[:])
	reduce(cc[:])
	uint2byte(x, cc[:n])
}

// reduceModOrder calculates a = a mod order of the curve.
func reduceModOrder(x []byte) {
	const n = (448 + bits.UintSize - 1) / bits.UintSize
	lx := len(x)
	if lx != Size && lx != 2*Size {
		panic("wrong input size")
	}
	la := (8*lx + bits.UintSize - 1) / bits.UintSize
	a := make([]uint, la)
	byte2uint(a, x)
	reduce(a)
	for i := range x {
		x[i] = 0
	}
	uint2byte(x, a[:n])
}

func reduce(a []uint) {
	const n = (448 + bits.UintSize - 1) / bits.UintSize
	const w = (32 * 8 / bits.UintSize)
	var res446, res448 [w]uint
	byte2uint(res446[:], residue446[:])
	byte2uint(res448[:], residue448[:])
	lc := len(a) - n + w + 1
	c := make([]uint, lc)

	for i := 0; i < 3; i++ {
		a1, a0 := a[n:], a[0:n]
		mul(c, res448[:], a1)
		for j := range a1 {
			a1[j] = 0
		}
		add(a, c[:w+len(a1)], a0)
	}

	last := a[n-1] >> (bits.UintSize - 2)
	a[n-1] &^= (uint(3) << (bits.UintSize - 2))

	a1, a0 := []uint{last}, a[0:n]
	mul(c, res446[:], a1)
	add(a, c[:w+len(a1)], a0)
}
