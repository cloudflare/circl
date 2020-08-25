package ted448

import (
	"encoding/binary"
	"math/bits"

	"github.com/cloudflare/circl/internal/conv"
)

const (
	// ScalarSize is the size (in bytes) of scalars.
	ScalarSize = 56
	//_N is the number of 64-bit words to store scalars.
	_N = 7 // 448 / 64
)

// Scalar represents a positive integer stored in little-endian order.
type Scalar [ScalarSize]byte

func (z Scalar) String() string { return conv.BytesLe2Hex(z[:]) }

type scalar64 [_N]uint64

func (z *scalar64) fromScalar(x *Scalar) {
	z[0] = binary.LittleEndian.Uint64(x[0*8 : 1*8])
	z[1] = binary.LittleEndian.Uint64(x[1*8 : 2*8])
	z[2] = binary.LittleEndian.Uint64(x[2*8 : 3*8])
	z[3] = binary.LittleEndian.Uint64(x[3*8 : 4*8])
	z[4] = binary.LittleEndian.Uint64(x[4*8 : 5*8])
	z[5] = binary.LittleEndian.Uint64(x[5*8 : 6*8])
	z[6] = binary.LittleEndian.Uint64(x[6*8 : 7*8])
}

func (z *scalar64) toScalar(x *Scalar) {
	binary.LittleEndian.PutUint64(x[0*8:1*8], z[0])
	binary.LittleEndian.PutUint64(x[1*8:2*8], z[1])
	binary.LittleEndian.PutUint64(x[2*8:3*8], z[2])
	binary.LittleEndian.PutUint64(x[3*8:4*8], z[3])
	binary.LittleEndian.PutUint64(x[4*8:5*8], z[4])
	binary.LittleEndian.PutUint64(x[5*8:6*8], z[5])
	binary.LittleEndian.PutUint64(x[6*8:7*8], z[6])
}

// isZero returns 1 if z=0.
func (z *scalar64) isZero() uint {
	z.modOrder()
	var z64 uint64
	for i := range z {
		z64 |= z[i]
	}
	z32 := uint32(z64&0xFFFFFFFF) | (uint32(z64>>32) & 0xFFFFFFF)
	return uint((uint64(z32) - 1) >> 63)
}

// cmov moves x into z if b=1.
func (z *scalar64) cmov(x *scalar64, b uint64) {
	m := -(b & 1)
	for i := range z {
		z[i] = (z[i] &^ m) | (x[i] & m)
	}
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

// leftShift shifts to the left the words of z returning the more significant word.
func (z *scalar64) leftShift(low uint64) uint64 {
	high := z[_N-1]
	for i := _N - 1; i > 0; i-- {
		z[i] = z[i-1]
	}
	z[0] = low
	return high
}

// reduceOneWord calculates z = z + 2^448*x such that the result fits in a Scalar.
func (z *scalar64) reduceOneWord(x uint64) {
	prod := (&scalar64{})[:]
	mulWord(prod, residue448[:], x)
	cc := add(z[:], z[:], prod)
	mulWord(prod, residue448[:], cc)
	add(z[:], z[:], prod)
}

// Sub calculates z = x-y mod order.
func (z *scalar64) sub(x, y *scalar64) {
	var t scalar64
	c := sub(z[:], x[:], y[:])
	sub(t[:], z[:], residue448[:])
	z.cmov(&t, c)
	z.modOrder()
}

// modOrder reduces z mod order.
func (z *scalar64) modOrder() {
	var o64, x scalar64
	o64.fromScalar(&order)
	// Performs: while (z >= order) { z = z-order }
	// At most 8 (eight) iterations reduce 3 bits by subtracting.
	for i := 0; i < 8; i++ {
		c := sub(x[:], z[:], o64[:]) // (c || x) = z-order
		z.cmov(&x, 1-c)              // if c != 0 { z = x }
	}
}

// FromBytes stores z = x mod order, where x is a number stored in little-endian order.
func (z *Scalar) FromBytes(x []byte) {
	n := len(x)
	nCeil := (n + 7) >> 3
	for i := range z {
		z[i] = 0
	}
	if nCeil < _N {
		copy(z[:], x)
		return
	}
	copy(z[:], x[8*(nCeil-_N):])
	var z64 scalar64
	z64.fromScalar(z)
	for i := nCeil - _N - 1; i >= 0; i-- {
		low := binary.LittleEndian.Uint64(x[8*i:])
		high := z64.leftShift(low)
		z64.reduceOneWord(high)
	}
	z64.modOrder()
	z64.toScalar(z)
}

// Red reduces z mod order.
func (z *Scalar) Red() { var t scalar64; t.fromScalar(z); t.modOrder(); t.toScalar(z) }

// Neg calculates z = -x mod order.
func (z *Scalar) Neg(x *Scalar) { z.Sub(&order, x) }

// Add calculates z = x+y mod order.
func (z *Scalar) Add(x, y *Scalar) {
	var z64, x64, y64, t scalar64
	x64.fromScalar(x)
	y64.fromScalar(y)
	c := add(z64[:], x64[:], y64[:])
	add(t[:], z64[:], residue448[:])
	z64.cmov(&t, c)
	z64.modOrder()
	z64.toScalar(z)
}

// Sub calculates z = x-y mod order.
func (z *Scalar) Sub(x, y *Scalar) {
	var z64, x64, y64 scalar64
	x64.fromScalar(x)
	y64.fromScalar(y)
	z64.sub(&x64, &y64)
	z64.toScalar(z)
}

// Mul calculates z = x*y mod order.
func (z *Scalar) Mul(x, y *Scalar) {
	var z64, x64, y64 scalar64
	x64.fromScalar(x)
	y64.fromScalar(y)
	coremul(&z64, &x64, &y64)
	z64.modOrder()
	z64.toScalar(z)
}

func coremul(z64, x64, y64 *scalar64) {
	var p64 scalar64
	prod := (&[_N + 1]uint64{})[:]
	mulWord(prod, x64[:], y64[_N-1])
	copy(p64[:], prod[:_N])
	p64.reduceOneWord(prod[_N])
	for i := _N - 2; i >= 0; i-- {
		h := p64.leftShift(0)
		p64.reduceOneWord(h)
		mulWord(prod, x64[:], y64[i])
		c := add(p64[:], p64[:], prod[:_N])
		p64.reduceOneWord(prod[_N] + c)
	}
	*z64 = p64
}

// Inv calculates z = 1/x mod order.
func (z *Scalar) Inv(x *Scalar) {
	var x64 scalar64
	x64.fromScalar(x)
	t := &scalar64{1}
	for i := 8*len(orderMinusTwo) - 1; i >= 0; i-- {
		coremul(t, t, t)
		b := (orderMinusTwo[i/8] >> uint(i%8)) & 1
		if b != 0 {
			coremul(t, t, &x64)
		}
	}
	t.modOrder()
	t.toScalar(z)
}
