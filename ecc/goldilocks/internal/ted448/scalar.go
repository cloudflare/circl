package ted448

import (
	"encoding/binary"
	"fmt"
	"io"
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

func (z Scalar) String() string { z.red(); return conv.BytesLe2Hex(z[:]) }

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

// mul calculates z = x * y.
func (z *scalar64) mul(x, y *scalar64) *scalar64 {
	var t scalar64
	prod := (&[_N + 1]uint64{})[:]
	mulWord(prod, x[:], y[_N-1])
	copy(t[:], prod[:_N])
	t.reduceOneWord(prod[_N])
	for i := _N - 2; i >= 0; i-- {
		h := t.leftShift(0)
		t.reduceOneWord(h)
		mulWord(prod, x[:], y[i])
		c := add(t[:], t[:], prod[:_N])
		t.reduceOneWord(prod[_N] + c)
	}
	*z = t
	return z
}

// sqrn calculates z = x^(2^n).
func (z *scalar64) sqrn(x *scalar64, n uint) *scalar64 {
	t := *x
	for i := uint(0); i < n; i++ {
		t.mul(&t, &t)
	}
	*z = t
	return z
}

// sqrnmul calculates z = x^(2^n) * y.
func (z *scalar64) sqrnmul(x *scalar64, n uint, y *scalar64) *scalar64 {
	return z.mul(z.sqrn(x, n), y)
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

func invertEndianness(v []byte) {
	for i := 0; i < len(v)/2; i++ {
		v[i], v[len(v)-1-i] = v[len(v)-1-i], v[i]
	}
}

// FromBytesBE stores z = x mod order, where x is a number stored in big-endian order.
func (z *Scalar) FromBytesBE(x []byte) {
	revX := make([]byte, len(x))
	copy(revX, x)
	invertEndianness(revX)
	z.FromBytesLE(revX)
}

// FromBytesLE stores z = x mod order, where x is a number stored in little-endian order.
func (z *Scalar) FromBytesLE(x []byte) {
	n := len(x)
	nCeil := (n + 7) >> 3
	*z = Scalar{}
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

// ToBytesBE returns the scalar byte representation in big-endian order.
func (z *Scalar) ToBytesBE() []byte { b := z.ToBytesLE(); invertEndianness(b); return b }

// ToBytesLE returns the scalar byte representation in little-endian order.
func (z *Scalar) ToBytesLE() []byte { z.red(); k := *z; return k[:] }

// MarshalBinary returns the scalar byte representation in big-endian order.
func (z *Scalar) MarshalBinary() ([]byte, error) { return z.ToBytesBE(), nil }

// UnmarshalBinary recovers the scalar from its byte representation in big-endian order.
func (z *Scalar) UnmarshalBinary(data []byte) error {
	if len(data) < ScalarSize {
		return io.ErrShortBuffer
	}

	var x Scalar
	copy(x[:], data[:ScalarSize])
	invertEndianness(x[:])
	// Check that input is fully-reduced, i.e., 0 <= data < order.
	if isLessThan(x[:], order[:]) == 0 {
		return fmt.Errorf("ted448: unmarshaling a scalar not in range [0, order)")
	}
	*z = x

	return nil
}

// isLessThan returns 1 if 0 <= x < y, and assumes that slices are of the
// same length and are interpreted in little-endian order.
func isLessThan(x, y []byte) int {
	i := len(x) - 1
	for i > 0 && x[i] == y[i] {
		i--
	}
	xi := int(x[i])
	yi := int(y[i])
	return ((xi - yi) >> (bits.UintSize - 1)) & 1
}

// red reduces z mod order.
func (z *Scalar) red() { var t scalar64; t.fromScalar(z); t.modOrder(); t.toScalar(z) }

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
	z64.mul(&x64, &y64)
	z64.modOrder()
	z64.toScalar(z)
}

// Inv calculates z = 1/x mod order.
func (z *Scalar) Inv(x *Scalar) {
	var x64 scalar64
	x64.fromScalar(x)

	x10 := (&scalar64{}).mul(&x64, &x64)            // x10 = 2 * 1
	x11 := (&scalar64{}).mul(x10, &x64)             // x11 = 1 + x10
	x100 := (&scalar64{}).mul(x11, &x64)            // x100 = 1 + x11
	x101 := (&scalar64{}).mul(x100, &x64)           // x101 = 1 + x100
	x1001 := (&scalar64{}).mul(x100, x101)          // x1001 = x100 + x101
	x1011 := (&scalar64{}).mul(x10, x1001)          // x1011 = x10 + x1001
	x1101 := (&scalar64{}).mul(x10, x1011)          // x1101 = x10 + x1011
	x1111 := (&scalar64{}).mul(x10, x1101)          // x1111 = x10 + x1101
	x10001 := (&scalar64{}).mul(x10, x1111)         // x10001 = x10 + x1111
	x10011 := (&scalar64{}).mul(x10, x10001)        // x10011 = x10 + x10001
	x10101 := (&scalar64{}).mul(x10, x10011)        // x10101 = x10 + x10011
	x10111 := (&scalar64{}).mul(x10, x10101)        // x10111 = x10 + x10101
	x11001 := (&scalar64{}).mul(x10, x10111)        // x11001 = x10 + x10111
	x11011 := (&scalar64{}).mul(x10, x11001)        // x11011 = x10 + x11001
	x11101 := (&scalar64{}).mul(x10, x11011)        // x11101 = x10 + x11011
	x11111 := (&scalar64{}).mul(x10, x11101)        // x11111 = x10 + x11101
	x111110 := (&scalar64{}).mul(x11111, x11111)    // x111110 = 2 * x11111
	x1111100 := (&scalar64{}).mul(x111110, x111110) // x1111100 = 2 * x111110
	i24, i41, i73, i129, t := &scalar64{}, &scalar64{}, &scalar64{},
		&scalar64{}, &scalar64{}
	x222, i262, i279, i298, i312, i331, i343, i365,
		i375, i396, i411, i431, i444, i464, i478, i498, iret := t, t,
		t, t, t, t, t, t, t, t, t, t, t, t, t, t, t

	i24.sqrnmul(x1111100, 5, x1111100)                                       // i24  = x1111100 << 5 + x1111100
	i41.sqrnmul(i41.sqrnmul(i24, 4, x111110), 11, i24)                       // i41  = (i24 << 4 + x111110) << 11 + i24
	i73.sqrnmul(i73.sqrnmul(i41, 4, x111110), 26, i41)                       // i73  = (i41 << 4 + x111110) << 26 + i41
	i129.sqrnmul(i73, 55, i73)                                               // i129 = i73 << 55 + i73
	x222.mul(x222.sqrnmul(i129, 110, x11), i129)                             // x222 = i129 << 110 + x11 + i129
	i262.sqrn(i262.sqrnmul(i262.sqrnmul(x222, 6, x11111), 7, x11001), 6)     // i262 = ((x222 << 6 + x11111) << 7 + x11001) << 6
	i279.sqrnmul(i279.sqrnmul(i279.mul(x10001, i262), 8, x11111), 6, x10011) // i279 = ((x10001 + i262) << 8 + x11111) << 6 + x10011
	i298.sqrn(i298.sqrnmul(i298.sqrnmul(i279, 5, x10001), 8, x10011), 4)     // i298 = ((i279 << 5 + x10001) << 8 + x10011) << 4
	i312.sqrnmul(i312.sqrnmul(i312.mul(x1011, i298), 6, x11011), 5, x1001)   // i312 = ((x1011 + i298) << 6 + x11011) << 5 + x1001
	i331.sqrn(i331.sqrnmul(i331.sqrnmul(i312, 6, x1101), 6, x11101), 5)      // i331 = ((i312 << 6 + x1101) << 6 + x11101) << 5
	i343.sqrnmul(i343.sqrnmul(i343.mul(x10101, i331), 5, x10001), 4, x1011)  // i343 = ((x10101 + i331) << 5 + x10001) << 4 + x1011
	i365.sqrn(i365.sqrnmul(i365.sqrnmul(i343, 5, x1001), 7, &x64), 8)        // i365 = ((i343 << 5 + x1001) << 7 + 1) << 8
	i375.sqrnmul(i375.sqrnmul(i375.mul(x1011, i365), 6, x11001), 1, &x64)    // i375 = 2*((x1011 + i365) << 6 + x11001) + 1
	i396.sqrn(i396.sqrnmul(i396.sqrnmul(i375, 9, x10011), 4, x1001), 6)      // i396 = ((i375 << 9 + x10011) << 4 + x1001) << 6
	i411.sqrnmul(i411.sqrnmul(i411.mul(x10001, i396), 5, x10111), 7, x1011)  // i411 = ((x10001 + i396) << 5 + x10111) << 7 + x1011
	i431.sqrn(i431.sqrnmul(i431.sqrnmul(i411, 7, x1111), 6, x10101), 5)      // i431 = ((i411 << 7 + x1111) << 6 + x10101) << 5
	i444.sqrnmul(i444.sqrnmul(i444.mul(x1001, i431), 8, x11011), 2, x11)     // i444 = ((x1001 + i431) << 8 + x11011) << 2 + x11
	i464.sqrn(i464.sqrnmul(i464.sqrnmul(i444, 5, x11), 7, x101), 6)          // i464 = ((i444 << 5 + x11) << 7 + x101) << 6
	i478.sqrnmul(i478.sqrnmul(i478.mul(x1001, i464), 6, x10101), 5, x1101)   // i478 = ((x1001 + i464) << 6 + x10101) << 5 + x1101
	i498.sqrn(i498.sqrnmul(i498.sqrnmul(i478, 3, x11), 9, x10001), 6)        // i498 = ((i478 << 3 + x11) << 9 + x10001) << 6
	iret.sqrnmul(iret.mul(x1111, i498), 4, &x64)                             // z    = (x1111 + i498) << 4 + 1
	iret.modOrder()
	iret.toScalar(z)
}
