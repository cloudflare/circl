package field

import "golang.org/x/sys/cpu"

// Arith448 provides arithmetic operations over GF(2^448-2^224-1)
type Arith448 interface {
	Prime() Element448              // Returns the prime modulus p=2^448-2^224-1
	CSel(x, y *Element448, b uint)  // Conditionally updates x with y if b!=0
	CSwap(x, y *Element448, b uint) // Conditionally interchages x and y if b!=0
	Add(z, x, y *Element448)        // Calculates z = x + y
	Sub(z, x, y *Element448)        // Calculates z = x - y
	AddSub(x, y *Element448)        // Calculates x,y = (x + y), (x - y)
	Mul(z, x, y *Element448)        // Calculates z = x * y
	Sqr(z, x *Element448)           // Calculates z = x^2
	Sqrn(z *Element448, n uint)     // Calculates z = x^{2^n}
	Modp(z *Element448)             // Calculates z = x mod p
	Div(z, x, y *Element448)        // Calculates z = x / y
	MulA24(z, x *Element448)        // Calculates z = 39082 * x
}

// Fp448 implements Arith448 interface
var Fp448 Arith448

type arith448 struct{}
type legacy448 struct{ arith448 }
type bmiAdx448 struct{ arith448 }

func init() {
	if cpu.X86.HasBMI2 && cpu.X86.HasADX {
		Fp448 = new(bmiAdx448)
	} else {
		Fp448 = new(legacy448)
	}
}

// Prime returns a copy of the prime p=2^{448}-2^{224}-1.
func (a arith448) Prime() Element448 {
	return Element448{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
}

// CSel updates x as follows:
//   if b=1:  x = y
//   if b=0:  x = x
//   else:  undefined
func (a arith448) CSel(x, y *Element448, b uint) { cSelect448(x, y, b) }

// CSwap updates x and y as follows:
//   if b=1:  x,y = y,x
//   if b=0:  x,y = x,y
//   else:  undefined
func (a arith448) CSwap(x, y *Element448, b uint) { cSwap448(x, y, b) }

// Sub calculates z = x-y
func (a arith448) Sub(z, x, y *Element448) { sub448(z, x, y) }

// AddSub calculates x,y = x+y,x-y
func (a arith448) AddSub(x, y *Element448) { addSub448(x, y) }

// Modp calculates z = z mod p
func (a arith448) Modp(z *Element448) { p := Fp448.Prime(); sub448(z, z, &p) }

// div448 calculates z = x/y
func div448(a Arith448, z, x, y *Element448) {
	var x0, x1, invY Element448
	invY = *y
	a.Sqrn(&invY, 1)
	a.Mul(&invY, &invY, y)
	x0 = invY
	a.Sqrn(&x0, 1)
	a.Mul(&x0, &x0, y)
	invY = x0
	a.Sqrn(&invY, 3)
	a.Mul(&invY, &invY, &x0)
	x1 = invY
	a.Sqrn(&x1, 6)
	a.Mul(&x1, &x1, &invY)
	invY = x1
	a.Sqrn(&invY, 12)
	a.Mul(&invY, &invY, &x1)
	a.Sqrn(&invY, 3)
	a.Mul(&invY, &invY, &x0)
	x1 = invY
	a.Sqrn(&x1, 27)
	a.Mul(&x1, &x1, &invY)
	invY = x1
	a.Sqrn(&invY, 54)
	a.Mul(&invY, &invY, &x1)
	a.Sqrn(&invY, 3)
	a.Mul(&invY, &invY, &x0)
	x1 = invY
	a.Sqrn(&x1, 111)
	a.Mul(&x1, &x1, &invY)
	invY = x1
	a.Sqrn(&invY, 1)
	a.Mul(&invY, &invY, y)
	a.Sqrn(&invY, 223)
	a.Mul(&invY, &invY, &x1)
	a.Sqrn(&invY, 2)
	a.Mul(&invY, &invY, y)
	a.Mul(z, x, &invY)
}

// Add calculates z = x+y
func (a legacy448) Add(z, x, y *Element448) { addLeg448(z, x, y) }

// Mul calculates z = x*y
func (a legacy448) Mul(z, x, y *Element448) {
	var b bigElement448
	intMul448(&b, x, y)
	reduce448(z, &b)
}

// Sqr calculates z = x^2
func (a legacy448) Sqr(z, x *Element448) { var b bigElement448; intSqr448(&b, x); reduce448(z, &b) }

// Sqrn calculates z = x^{2^n}
func (a legacy448) Sqrn(z *Element448, n uint) { var b bigElement448; sqrn448(z, &b, n) }

// MulA24 calculates z = x*A24
func (a legacy448) MulA24(z, x *Element448) { mulA24448(z, x) }

// Div calculates z = x/y
func (a legacy448) Div(z, x, y *Element448) { div448(a, z, x, y) }

// Add calculates z = x+y
func (a bmiAdx448) Add(z, x, y *Element448) { addAdx448(z, x, y) }

// Mul calculates z = x*y
func (a bmiAdx448) Mul(z, x, y *Element448) {
	var b bigElement448
	intMulAdx448(&b, x, y)
	reduceAdx448(z, &b)
}

// Sqr calculates z = x^2
func (a bmiAdx448) Sqr(z, x *Element448) {
	var b bigElement448
	intSqrAdx448(&b, x)
	reduceAdx448(z, &b)
}

// Sqrn calculates z = x^{2^n}
func (a bmiAdx448) Sqrn(z *Element448, n uint) { var b bigElement448; sqrnAdx448(z, &b, n) }

// MulA24 calculates z = x*A24
func (a bmiAdx448) MulA24(z, x *Element448) { mulA24Adx448(z, x) }

// Div calculates z = x/y
func (a bmiAdx448) Div(z, x, y *Element448) { div448(a, z, x, y) }

// Functions defined in assembler files

//go:noescape
func cSelect448(x, y *Element448, b uint)

//go:noescape
func cSwap448(x, y *Element448, b uint)

//go:noescape
func addSub448(z, x *Element448)

//go:noescape
func addLeg448(z, x, y *Element448)

//go:noescape
func addAdx448(z, x, y *Element448)

//go:noescape
func sub448(z, x, y *Element448)

//go:noescape
func mulA24448(z, x *Element448)

//go:noescape
func mulA24Adx448(z, x *Element448)

//go:noescape
func intMul448(z *bigElement448, x, y *Element448)

//go:noescape
func intMulAdx448(z *bigElement448, x, y *Element448)

//go:noescape
func intSqr448(z *bigElement448, x *Element448)

//go:noescape
func intSqrAdx448(z *bigElement448, x *Element448)

//go:noescape
func reduce448(z *Element448, x *bigElement448)

//go:noescape
func reduceAdx448(z *Element448, x *bigElement448)

//go:noescape
func sqrn448(z *Element448, buffer *bigElement448, times uint)

//go:noescape
func sqrnAdx448(z *Element448, buffer *bigElement448, times uint)
