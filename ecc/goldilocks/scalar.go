package goldilocks

import (
	"encoding/binary"
	"math/bits"
	"unsafe"
)

// ScalarSize is the size (in bytes) of scalars.
const ScalarSize = 56 // 448 / 8

//_N is the number of 64-bit words to store scalars.
const _N = 7 // 448 / 64

// Scalar represents a positive integer stored in little-endian order.
type Scalar [ScalarSize]byte

type scalar64 [_N]uint64

func (z *Scalar) getScalar64() *scalar64 { return (*scalar64)(unsafe.Pointer(z)) }

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

// Cmov moves x into z if b=1.
func (z *scalar64) Cmov(b uint64, x *scalar64) {
	m := uint64(0) - b
	for i := range z {
		z[i] = (z[i] &^ m) | (x[i] & m)
	}
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

// modOrder reduces z mod order.
func (z *scalar64) modOrder() {
	x := &scalar64{}
	o64 := order.getScalar64()[:]
	// Performs: while (z >= order) { z = z-order }
	for i := 0; i < 8; i++ {
		c := sub(x[:], z[:], o64) // (c || x) = z-order
		z.Cmov(1-c, x)            // if c != 0 { z = x }
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
	z64 := z.getScalar64()
	for i := nCeil - _N - 1; i >= 0; i-- {
		low := binary.LittleEndian.Uint64(x[8*i:])
		high := z64.leftShift(low)
		z64.reduceOneWord(high)
	}
	z64.modOrder()
}

// divBy4 calculates x = x/4 mod order.
func (z *Scalar) divBy4() { z.Mul(z, &invFour) }

// Red reduces z mod order.
func (z *Scalar) Red() { z.getScalar64().modOrder() }

// Neg calculates z = -z mod order.
func (z *Scalar) Neg() { z.Sub(&order, z) }

// Add calculates z = x+y mod order.
func (z *Scalar) Add(x, y *Scalar) {
	t := &scalar64{}
	x64 := x.getScalar64()[:]
	y64 := y.getScalar64()[:]
	z64 := z.getScalar64()
	c := add(z64[:], x64, y64)
	add(t[:], z64[:], residue448[:])
	z64.Cmov(c, t)
	z64.modOrder()
}

// Sub calculates z = x-y mod order.
func (z *Scalar) Sub(x, y *Scalar) {
	t := &scalar64{}
	x64 := x.getScalar64()[:]
	y64 := y.getScalar64()[:]
	z64 := z.getScalar64()
	c := sub(z64[:], x64, y64)
	sub(t[:], z64[:], residue448[:])
	z64.Cmov(c, t)
	z64.modOrder()
}

// Mul calculates z = x*y mod order.
func (z *Scalar) Mul(x, y *Scalar) {
	t := &scalar64{}
	prod := (&[_N + 1]uint64{})[:]
	x64 := x.getScalar64()[:]
	y64 := y.getScalar64()[:]
	z64 := z.getScalar64()
	mulWord(prod, x64, y64[_N-1])
	copy(t[:], prod[:_N])
	t.reduceOneWord(prod[_N])
	for i := _N - 2; i >= 0; i-- {
		h := t.leftShift(0)
		t.reduceOneWord(h)
		mulWord(prod, x64, y64[i])
		c := add(t[:], t[:], prod[:_N])
		t.reduceOneWord(prod[_N] + c)
	}
	t.modOrder()
	*z64 = *t
}
