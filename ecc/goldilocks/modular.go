package goldilocks

import (
	"encoding/binary"
	"math/bits"
	"unsafe"

	fp "github.com/cloudflare/circl/math/fp448"
)

// invFour is 1/4 mod order.
var invFour = [fp.Size]byte{
	0x3d, 0x11, 0xd6, 0xaa, 0xa4, 0x30, 0xde, 0x48,
	0xd5, 0x63, 0x71, 0xa3, 0x9c, 0x30, 0x5b, 0x08,
	0xa4, 0x8d, 0xb5, 0x6b, 0xd2, 0xb6, 0x13, 0x71,
	0xfa, 0x88, 0x32, 0xdf, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
}

// add calculates z = x + y. Assumes len(z) > max(len(x),len(y)).
func add(z, x, y []uint64) uint64 {
	l, L, zz := len(x), len(y), y
	if l > L {
		l, L, zz = L, l, x
	}
	c := uint64(0)
	for i := 0; i < l; i++ {
		z[i], c = bits.Add64(x[i], y[i], c)
	}
	for i := l; i < L; i++ {
		z[i], c = bits.Add64(zz[i], 0, c)
	}
	return c
}

// sub calculates z = x - y. Assumes len(z) > max(len(x),len(y)).
func sub(z, x, y []uint64) uint64 {
	l, L, zz := len(x), len(y), y
	if l > L {
		l, L, zz = L, l, x
	}
	c := uint64(0)
	for i := 0; i < l; i++ {
		z[i], c = bits.Sub64(x[i], y[i], c)
	}
	for i := l; i < L; i++ {
		z[i], c = bits.Sub64(zz[i], 0, c)
	}
	return c
}

// mulWord calculates z = x * y. Assumes len(z) >= len(x)+1.
func mulWord(z, x []uint64, y uint64) {
	for i := range z {
		z[i] = 0
	}
	carry := uint64(0)
	for i := range x {
		hi, lo := bits.Mul64(x[i], y)
		lo, cc := bits.Add64(lo, z[i], 0)
		hi, _ = bits.Add64(hi, 0, cc)
		z[i], cc = bits.Add64(lo, carry, 0)
		carry, _ = bits.Add64(hi, 0, cc)
	}
	z[len(x)] = carry
}

// cMovUint64 loads x (if b=1) into z.
func cMovUint64(b uint64, z, x []uint64) {
	m := uint64(0) - b
	for i := range z {
		z[i] = (z[i] & m) | (x[i] &^ m)
	}
}

// reduceSliceTo448 applies the equivalence 2^448=residue448 (mod order) until x has 448 bits.
func reduceSliceTo448(x []uint64) {
	prod := (&[_N]uint64{})[:]
	for L := len(x); L > _N; L-- {
		high := &x[L-1]
		low := x[L-_N-1 : L-1]
		mulWord(prod, residue448[:], *high)
		carry := add(low, low, prod)
		mulWord(prod, residue448[:], carry)
		add(low, low, prod)
		*high = 0
	}
}

// reduceModOrder calculates c = a mod order of the curve.
func reduceModOrder(c, a []byte) {
	n := len(a)
	nCeil := (n + 7) >> 3
	if nCeil < _N {
		copy(c, a)
		return
	}

	nFloor := n >> 3
	x64 := make([]uint64, nCeil)
	for i := 0; i < nFloor; i++ {
		x64[i] = binary.LittleEndian.Uint64(a[8*i:])
	}
	for i, j := 8*nFloor, uint(0); i < n; i++ {
		x64[nFloor] |= uint64(a[i]) << (8 * j)
		j++
	}

	reduceSliceTo448(x64)

	x := x64[:_N]
	y := (&[_N]uint64{})[:]
	p := (*[_N]uint64)(unsafe.Pointer(&order))

	// while (x >= p) { x = x-p }
	for i := 0; i < 8; i++ {
		c := sub(y, x, p[:]) // (c || y) = x-p
		cMovUint64(c, x, y)  // if c != 0 { x = y }
	}
	for i := 0; i < _N; i++ {
		binary.LittleEndian.PutUint64(c[8*i:], x[i])
	}
}

// cNegate calculates -a mod order if b=1.
func cNegate(a []byte, b int) {
	y := (&[_N]uint64{})[:]
	x := (*[_N]uint64)(unsafe.Pointer(&a))
	p := (*[_N]uint64)(unsafe.Pointer(&order))
	sub(y, p[:], x[:])
	cMovUint64(uint64(b), x[:], y)
}

// div4 calculates x = x/4 mod order.
func div4(x []byte) {
	// 	const n = (448 + bits.UintSize - 1) / bits.UintSize
	// 	const l = (8*ScalarSize + bits.UintSize - 1) / bits.UintSize
	// 	var xx, inv4 [l]uint
	// 	var cc [2 * l]uint
	// 	byte2uint(xx[:], x)
	// 	byte2uint(inv4[:], invFour[:])
	// 	mul(cc[:], xx[:], inv4[:])
	// 	reduce(cc[:])
	// 	uint2byte(x, cc[:n])
}
