// +build amd64

package fp448

import (
	"golang.org/x/sys/cpu"
)

var hasBmi2Adx = cpu.X86.HasBMI2 && cpu.X86.HasADX

// Cmov assigns y to x if n is non-zero 0.
//go:noescape
func Cmov(x, y *Elt, n uint)

// Cswap interchages x and y if n is non-zero 0
//go:noescape
func Cswap(x, y *Elt, n uint)

// Add calculates z = x+y mod p
//go:noescape
func Add(z, x, y *Elt)

// Sub calculates z = x-y mod p
//go:noescape
func Sub(z, x, y *Elt)

// AddSub calculates (x,y) = (x+y mod p, x-y mod p)
//go:noescape
func AddSub(x, y *Elt)

// Mul calculates z = x*y mod p
//go:noescape
func Mul(z, x, y *Elt)

// Sqr calculates z = x^2 mod p
//go:noescape
func Sqr(z, x *Elt)
