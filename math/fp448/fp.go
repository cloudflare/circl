// Package fp448 provides prime field arithmetic over GF(2^448-2^224-1).
package fp448

import "github.com/cloudflare/circl/internal/conv"

// Size in bytes of an element.
const Size = 56

// Elt is a prime field element.
type Elt [Size]byte

func (e Elt) String() string { return conv.BytesLe2Hex(e[:]) }

// p is the prime modulus 2^448-2^224-1
var p = Elt{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

// P returns the prime modulus 2^448-2^224-1.
func P() Elt { return p }

// ToBytes returns the little-endian byte representation of x.
func ToBytes(b []byte, x *Elt) {
	if len(b) != Size {
		panic("wrong size")
	}
	Modp(x)
	copy(b, x[:])
}

// IsZero returns true if x is equal to 0.
func IsZero(x *Elt) bool { Modp(x); return *x == Elt{} }

// SetOne assigns x=1.
func SetOne(x *Elt) { *x = Elt{}; x[0] = 1 }

// Neg calculates z = -x.
func Neg(z, x *Elt) { Sub(z, &p, x) }

// Modp ensures that z is between [0,p-1].
func Modp(z *Elt) { Sub(z, z, &p) }

// Inv calculates z = 1/x mod p.
func Inv(z, x *Elt) {
	x0, x1, x2 := &Elt{}, &Elt{}, &Elt{}
	Sqr(x2, x)
	Mul(x2, x2, x)
	Sqr(x0, x2)
	Mul(x0, x0, x)
	Sqr(x2, x0)
	Sqr(x2, x2)
	Sqr(x2, x2)
	Mul(x2, x2, x0)
	Sqr(x1, x2)
	for i := 0; i < 5; i++ {
		Sqr(x1, x1)
	}
	Mul(x1, x1, x2)
	Sqr(x2, x1)
	for i := 0; i < 11; i++ {
		Sqr(x2, x2)
	}
	Mul(x2, x2, x1)
	Sqr(x2, x2)
	Sqr(x2, x2)
	Sqr(x2, x2)
	Mul(x2, x2, x0)
	Sqr(x1, x2)
	for i := 0; i < 26; i++ {
		Sqr(x1, x1)
	}
	Mul(x1, x1, x2)
	Sqr(x2, x1)
	for i := 0; i < 53; i++ {
		Sqr(x2, x2)
	}
	Mul(x2, x2, x1)
	Sqr(x2, x2)
	Sqr(x2, x2)
	Sqr(x2, x2)
	Mul(x2, x2, x0)
	Sqr(x1, x2)
	for i := 0; i < 110; i++ {
		Sqr(x1, x1)
	}
	Mul(x1, x1, x2)
	Sqr(x2, x1)
	Mul(x2, x2, x)
	for i := 0; i < 223; i++ {
		Sqr(x2, x2)
	}
	Mul(x2, x2, x1)
	Sqr(x2, x2)
	Sqr(x2, x2)
	Mul(z, x2, x)
}

// Cmov assigns y to x if n is 1.
func Cmov(x, y *Elt, n uint) { cmov(x, y, n) }

// Cswap interchages x and y if n is 1.
func Cswap(x, y *Elt, n uint) { cswap(x, y, n) }

// Add calculates z = x+y mod p.
func Add(z, x, y *Elt) { add(z, x, y) }

// Sub calculates z = x-y mod p
func Sub(z, x, y *Elt) { sub(z, x, y) }

// AddSub calculates (x,y) = (x+y mod p, x-y mod p).
func AddSub(x, y *Elt) { addsub(x, y) }

// Mul calculates z = x*y mod p.
func Mul(z, x, y *Elt) { mul(z, x, y) }

// Sqr calculates z = x^2 mod p.
func Sqr(z, x *Elt) { sqr(z, x) }
