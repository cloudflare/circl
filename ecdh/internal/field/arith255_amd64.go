package field

import cpu "github.com/cloudflare/circl/utils"

// Arith255 provides arithmetic operations over GF(2^255-19)
type Arith255 interface {
	Prime() Element255              // Returns the prime modulus p=2^255-19
	CSel(x, y *Element255, b uint)  // Conditionally updates x with y if b!=0
	CSwap(x, y *Element255, b uint) // Conditionally interchages x and y if b!=0
	Add(z, x, y *Element255)        // Calculates z = x + y
	Sub(z, x, y *Element255)        // Calculates z = x - y
	AddSub(x, y *Element255)        // Calculates x,y = (x + y), (x - y)
	Mul(z, x, y *Element255)        // Calculates z = x * y
	Sqr(z, x *Element255)           // Calculates z = x^2
	Sqrn(z *Element255, n uint)     // Calculates z = x^{2^n}
	Div(z, x, y *Element255)        // Calculates z = x / y
	MulA24(z, x *Element255)        // Calculates z = 121666 * x
	Modp(z *Element255)             // Calculates z = x mod p
}

// Fp255 implements Arith255 interface
var Fp255 Arith255

type arith255 struct{}
type legacy255 struct{ arith255 }
type bmiAdx255 struct{ arith255 }

func init() {
	if cpu.X86.HasBMI2 && cpu.X86.HasADX {
		Fp255 = new(bmiAdx255)
	} else {
		Fp255 = new(legacy255)
	}
}

// Prime returns a copy of the prime p=2^{255}-19.
func (a arith255) Prime() Element255 {
	return Element255{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}
}

// CSel updates x as follows:
//   if b=1:  x = y
//   if b=0:  x = x
//   else:  undefined
func (a arith255) CSel(x, y *Element255, b uint) { cSelect255(x, y, b) }

// CSwap updates x and y as follows:
//   if b=1:  x,y = y,x
//   if b=0:  x,y = x,y
//   else:  undefined
func (a arith255) CSwap(x, y *Element255, b uint) { cSwap255(x, y, b) }

// Sub calculates z = x-y
func (a arith255) Sub(z, x, y *Element255) { sub255(z, x, y) }

// AddSub calculates x,y = x+y,x-y
func (a arith255) AddSub(x, y *Element255) { addSub255(x, y) }

// Modp calculates z = z mod p
func (a arith255) Modp(z *Element255) { moduloP255(z) }

// div255 calculates z = x/y
func div255(a Arith255, z, x, y *Element255) {
	var x0, x1, x2, invY Element255
	invY = *y
	a.Sqrn(&invY, 1)
	x1 = invY
	a.Sqrn(&x1, 2)
	a.Mul(&x0, &x1, y)
	a.Mul(&invY, &invY, &x0)
	x1 = invY
	a.Sqrn(&x1, 1)
	a.Mul(&x0, &x0, &x1)
	x1 = x0
	a.Sqrn(&x1, 5)
	a.Mul(&x0, &x0, &x1)
	x1 = x0
	a.Sqrn(&x1, 10)
	a.Mul(&x1, &x1, &x0)
	x2 = x1
	a.Sqrn(&x2, 20)
	a.Mul(&x2, &x2, &x1)
	a.Sqrn(&x2, 10)
	a.Mul(&x2, &x0, &x2)
	x0 = x2
	a.Sqrn(&x0, 50)
	a.Mul(&x0, &x0, &x2)
	x1 = x0
	a.Sqrn(&x1, 100)
	a.Mul(&x1, &x1, &x0)
	a.Sqrn(&x1, 50)
	a.Mul(&x1, &x1, &x2)
	a.Sqrn(&x1, 5)
	a.Mul(&invY, &invY, &x1)
	a.Mul(z, x, &invY)
}

// Add calculates z = x+y
func (a legacy255) Add(z, x, y *Element255) { addLeg255(z, x, y) }

// Mul calculates z = x*y
func (a legacy255) Mul(z, x, y *Element255) {
	var b bigElement255
	intMul255(&b, x, y)
	reduce255(z, &b)
}

// Sqr calculates z = x^2
func (a legacy255) Sqr(z, x *Element255) { var b bigElement255; intSqr255(&b, x); reduce255(z, &b) }

// Sqrn calculates z = x^{2^n}
func (a legacy255) Sqrn(z *Element255, n uint) { var b bigElement255; sqrn255(z, &b, n) }

// MulA24 calculates z = x*A24
func (a legacy255) MulA24(z, x *Element255) { mulA24255(z, x) }

// Div calculates z = x/y
func (a legacy255) Div(z, x, y *Element255) { div255(a, z, x, y) }

// Add calculates z = x+y
func (a bmiAdx255) Add(z, x, y *Element255) { addAdx255(z, x, y) }

// Mul calculates z = x*y
func (a bmiAdx255) Mul(z, x, y *Element255) {
	var b bigElement255
	intMulAdx255(&b, x, y)
	reduceAdx255(z, &b)
}

// Sqr calculates z = x^2
func (a bmiAdx255) Sqr(z, x *Element255) {
	var b bigElement255
	intSqrAdx255(&b, x)
	reduceAdx255(z, &b)
}

// Sqrn calculates z = x^{2^n}
func (a bmiAdx255) Sqrn(z *Element255, n uint) { var b bigElement255; sqrnAdx255(z, &b, n) }

// MulA24 calculates z = x*A24
func (a bmiAdx255) MulA24(z, x *Element255) { mulA24Adx255(z, x) }

// Div calculates z = x/y
func (a bmiAdx255) Div(z, x, y *Element255) { div255(a, z, x, y) }

// Functions defined in assembler files

//go:noescape
func cSelect255(x, y *Element255, b uint)

//go:noescape
func cSwap255(x, y *Element255, b uint)

//go:noescape
func addSub255(z, x *Element255)

//go:noescape
func addLeg255(z, x, y *Element255)

//go:noescape
func addAdx255(z, x, y *Element255)

//go:noescape
func sub255(z, x, y *Element255)

//go:noescape
func mulA24255(z, x *Element255)

//go:noescape
func mulA24Adx255(z, x *Element255)

//go:noescape
func intMul255(z *bigElement255, x, y *Element255)

//go:noescape
func intMulAdx255(z *bigElement255, x, y *Element255)

//go:noescape
func intSqr255(z *bigElement255, x *Element255)

//go:noescape
func intSqrAdx255(z *bigElement255, x *Element255)

//go:noescape
func reduce255(z *Element255, x *bigElement255)

//go:noescape
func reduceAdx255(z *Element255, x *bigElement255)

//go:noescape
func sqrn255(z *Element255, buffer *bigElement255, times uint)

//go:noescape
func sqrnAdx255(z *Element255, buffer *bigElement255, times uint)

//go:noescape
func moduloP255(z *Element255)
