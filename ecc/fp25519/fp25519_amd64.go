// @author Armando Faz

// +build amd64

// Package fp25519 implements prime field arithmetic for p=2^{255}-19.
package fp25519

import cpu "github.com/cloudflare/circl/utils"

// SizeElement is the size in bytes of an element in Fp25519.
const SizeElement = 32

// Element represents a prime field element.
type Element = [SizeElement]byte

// Add adds x and y and stores in z
var Add func(z, x, y *Element)

// IntMul multiplies x and y and stores in z
var IntMul func(z *[2 * SizeElement]byte, x, y *Element)

// IntSqr squares x and stores in z
var IntSqr func(z *[2 * SizeElement]byte, x *Element)

// Sqrn calculates x^{2^times} modulo p and stores in z
// Using a buffer for storing intermediate results.
var Sqrn func(z *Element, buffer *[2 * SizeElement]byte, times uint)

// Reduce finds z congruent to x modulo p such that 0<z<2^(SizeElement*8)
var Reduce func(z *Element, x *[2 * SizeElement]byte)

// MulA24 multiplies A24*x=121666*x and stores in z
var MulA24 func(z, x *Element)

// AddSub calculates z,x = z+x,z-x
//go:noescape
func AddSub(z, x *Element)

// Sub subtracts y from x and stores in z
//go:noescape
func Sub(z, x, y *Element)

// ModuloP reduces x modulo p and stores in z
//go:noescape
func ModuloP(z *Element)

// CSelect moves y into x if b=1 in constant-time.
//go:noescape
func CSelect(x, y *Element, b int)

// CSwap exchanges x and y if b=1 in constant-time.
//go:noescape
func CSwap(x, y *Element, b int)

//go:noescape
func addLeg(z, x, y *Element)

//go:noescape
func addAdx(z, x, y *Element)

//go:noescape
func intMul(z *[2 * SizeElement]byte, x, y *Element)

//go:noescape
func intMulAdx(z *[2 * SizeElement]byte, x, y *Element)

//go:noescape
func intSqr(z *[2 * SizeElement]byte, x *Element)

//go:noescape
func intSqrAdx(z *[2 * SizeElement]byte, x *Element)

//go:noescape
func reduce(z *Element, x *[2 * SizeElement]byte)

//go:noescape
func reduceAdx(z *Element, x *[2 * SizeElement]byte)

//go:noescape
func mulA24(z, x *Element)

//go:noescape
func mulA24Adx(z, x *Element)

//go:noescape
func sqrn(z *Element, buffer *[2 * SizeElement]byte, times uint)

//go:noescape
func sqrnAdx(z *Element, buffer *[2 * SizeElement]byte, times uint)

// Div calculates x/y and stores in z
func Div(z, x, y *Element) {
	var buffer [2 * SizeElement]byte
	var x0, x1, x2, invY Element

	T := [5]*Element{&x0, &invY, &x1, &x2, y}

	if cpu.X86.HasBMI2 && cpu.X86.HasADX {
		*(T[1]) = *(T[4])
		sqrnAdx(T[1], &buffer, 1)
		*(T[2]) = *(T[1])
		sqrnAdx(T[2], &buffer, 2)
		intMulAdx(&buffer, T[2], T[4])
		reduceAdx(T[0], &buffer)
		intMulAdx(&buffer, T[1], T[0])
		reduceAdx(T[1], &buffer)
		*(T[2]) = *(T[1])
		sqrnAdx(T[2], &buffer, 1)
		intMulAdx(&buffer, T[0], T[2])
		reduceAdx(T[0], &buffer)
		*(T[2]) = *(T[0])
		sqrnAdx(T[2], &buffer, 5)
		intMulAdx(&buffer, T[0], T[2])
		reduceAdx(T[0], &buffer)
		*(T[2]) = *(T[0])
		sqrnAdx(T[2], &buffer, 10)
		intMulAdx(&buffer, T[2], T[0])
		reduceAdx(T[2], &buffer)
		*(T[3]) = *(T[2])
		sqrnAdx(T[3], &buffer, 20)
		intMulAdx(&buffer, T[3], T[2])
		reduceAdx(T[3], &buffer)
		sqrnAdx(T[3], &buffer, 10)
		intMulAdx(&buffer, T[0], T[3])
		reduceAdx(T[3], &buffer)
		*(T[0]) = *(T[3])
		sqrnAdx(T[0], &buffer, 50)
		intMulAdx(&buffer, T[0], T[3])
		reduceAdx(T[0], &buffer)
		*(T[2]) = *(T[0])
		sqrnAdx(T[2], &buffer, 100)
		intMulAdx(&buffer, T[2], T[0])
		reduceAdx(T[2], &buffer)
		sqrnAdx(T[2], &buffer, 50)
		intMulAdx(&buffer, T[2], T[3])
		reduceAdx(T[2], &buffer)
		sqrnAdx(T[2], &buffer, 5)
		intMulAdx(&buffer, T[1], T[2])
		reduceAdx(T[1], &buffer)
		intMulAdx(&buffer, x, &invY)
		reduceAdx(z, &buffer)
	} else {
		*(T[1]) = *(T[4])
		sqrn(T[1], &buffer, 1)
		*(T[2]) = *(T[1])
		sqrn(T[2], &buffer, 2)
		intMul(&buffer, T[2], T[4])
		reduce(T[0], &buffer)
		intMul(&buffer, T[1], T[0])
		reduce(T[1], &buffer)
		*(T[2]) = *(T[1])
		sqrn(T[2], &buffer, 1)
		intMul(&buffer, T[0], T[2])
		reduce(T[0], &buffer)
		*(T[2]) = *(T[0])
		sqrn(T[2], &buffer, 5)
		intMul(&buffer, T[0], T[2])
		reduce(T[0], &buffer)
		*(T[2]) = *(T[0])
		sqrn(T[2], &buffer, 10)
		intMul(&buffer, T[2], T[0])
		reduce(T[2], &buffer)
		*(T[3]) = *(T[2])
		sqrn(T[3], &buffer, 20)
		intMul(&buffer, T[3], T[2])
		reduce(T[3], &buffer)
		sqrn(T[3], &buffer, 10)
		intMul(&buffer, T[0], T[3])
		reduce(T[3], &buffer)
		*(T[0]) = *(T[3])
		sqrn(T[0], &buffer, 50)
		intMul(&buffer, T[0], T[3])
		reduce(T[0], &buffer)
		*(T[2]) = *(T[0])
		sqrn(T[2], &buffer, 100)
		intMul(&buffer, T[2], T[0])
		reduce(T[2], &buffer)
		sqrn(T[2], &buffer, 50)
		intMul(&buffer, T[2], T[3])
		reduce(T[2], &buffer)
		sqrn(T[2], &buffer, 5)
		intMul(&buffer, T[1], T[2])
		reduce(T[1], &buffer)
		intMul(&buffer, x, &invY)
		reduce(z, &buffer)
	}
}

// Prime returns a copy of the prime p=2^{255}-19.
func Prime() (p Element) {
	return Element{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}
}

func init() {
	if cpu.X86.HasADX {
		Add = addAdx
	} else {
		Add = addLeg
	}
	if cpu.X86.HasBMI2 && cpu.X86.HasADX {
		IntMul = intMulAdx
		IntSqr = intSqrAdx
		Reduce = reduceAdx
		MulA24 = mulA24Adx
		Sqrn = sqrnAdx
	} else {
		IntMul = intMul
		IntSqr = intSqr
		Reduce = reduce
		MulA24 = mulA24
		Sqrn = sqrn
	}
}
