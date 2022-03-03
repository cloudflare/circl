package fourq

import (
	"math/big"

	"github.com/cloudflare/circl/internal/conv"
)

var modulusP = Fp{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
}

// SizeFp is the length in bytes to represent an element in the base field.
const SizeFp = 16

// Fp is an element (in littleEndian order) of prime field GF(2^127-1).
type Fp [SizeFp]byte

func (f *Fp) String() string       { return conv.BytesLe2Hex(f[:]) }
func (f *Fp) isZero() bool         { fpMod(f); return *f == Fp{} }
func (f *Fp) toBigInt() *big.Int   { fpMod(f); return conv.BytesLe2BigInt(f[:]) }
func (f *Fp) setBigInt(b *big.Int) { conv.BigInt2BytesLe((*f)[:], b); fpMod(f) }
func (f *Fp) toBytes(buf []byte) {
	if len(buf) == SizeFp {
		fpMod(f)
		copy(buf, f[:])
	}
}

func (f *Fp) fromBytes(buf []byte) bool {
	if len(buf) == SizeFp {
		if (buf[SizeFp-1] >> 7) == 0 {
			copy(f[:], buf)
			fpMod(f)
			return true
		}
	}
	return false
}
func fpNeg(c, a *Fp) { fpSub(c, &modulusP, a) }

// fqSgn returns the sign of an element.
//
//	-1 if x >  (p+1)/2
//	 0 if x == 0
//	+1 if x >  (p+1)/2.
func fpSgn(c *Fp) int {
	s := 0
	if !c.isZero() {
		b := int(c[SizeFp-1]>>6) & 0x1
		s = 1 - (b << 1)
	}
	return s
}

// fpTwo1251 sets c = a^(2^125-1).
func fpTwo1251(c, a *Fp) {
	t1, t2, t3, t4, t5 := &Fp{}, &Fp{}, &Fp{}, &Fp{}, &Fp{}

	fpSqr(t2, a)
	fpMul(t2, t2, a)
	fpSqr(t3, t2)
	fpSqr(t3, t3)
	fpMul(t3, t3, t2)
	fpSqr(t4, t3)
	fpSqr(t4, t4)
	fpSqr(t4, t4)
	fpSqr(t4, t4)
	fpMul(t4, t4, t3)
	fpSqr(t5, t4)
	for i := 0; i < 7; i++ {
		fpSqr(t5, t5)
	}
	fpMul(t5, t5, t4)
	fpSqr(t2, t5)
	for i := 0; i < 15; i++ {
		fpSqr(t2, t2)
	}
	fpMul(t2, t2, t5)
	fpSqr(t1, t2)
	for i := 0; i < 31; i++ {
		fpSqr(t1, t1)
	}
	fpMul(t1, t1, t2)
	for i := 0; i < 32; i++ {
		fpSqr(t1, t1)
	}
	fpMul(t1, t2, t1)
	for i := 0; i < 16; i++ {
		fpSqr(t1, t1)
	}
	fpMul(t1, t1, t5)
	for i := 0; i < 8; i++ {
		fpSqr(t1, t1)
	}
	fpMul(t1, t1, t4)
	for i := 0; i < 4; i++ {
		fpSqr(t1, t1)
	}
	fpMul(t1, t1, t3)
	fpSqr(t1, t1)
	fpMul(c, a, t1)
}

// fpInv sets z to a^(-1) mod p.
func fpInv(z, a *Fp) {
	t := &Fp{}
	fpTwo1251(t, a)
	fpSqr(t, t)
	fpSqr(t, t)
	fpMul(z, t, a)
}
