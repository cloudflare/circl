// +build amd64

package ecdh

import (
	"github.com/cloudflare/circl/ecdh/internal/field"
	"golang.org/x/sys/cpu"
)

func init() {
	x255.size = field.SizeFp255
	x255.n = 255
	x255.h = 3
	x255.xCoord = 9
	x255.table = tableBasePoint255[:]
	x255.pointS = pointS255[:]
	x255.pointGS = pointGS255[:]
	x255.toAffine = func(x, z []byte) []byte {
		var xDivZ, X, Z field.Element255
		copy(X[:], x)
		copy(Z[:], z)
		field.Fp255.Div(&xDivZ, &X, &Z)
		field.Fp255.Modp(&xDivZ)
		return xDivZ[:]
	}

	x448.size = field.SizeFp448
	x448.n = 448
	x448.h = 2
	x448.xCoord = 5
	x448.table = tableBasePoint448[:]
	x448.pointS = pointS448[:]
	x448.pointGS = pointGS448[:]
	x448.toAffine = func(x, z []byte) []byte {
		var xDivZ, X, Z field.Element448
		copy(X[:], x)
		copy(Z[:], z)
		field.Fp448.Div(&xDivZ, &X, &Z)
		field.Fp448.Modp(&xDivZ)
		return xDivZ[:]
	}

	if cpu.X86.HasBMI2 && cpu.X86.HasADX {
		x255.ladderStep = ladderStepBmi2AdxX255
		x255.double = doubleBmi2AdxX255
		x255.difadd = difAdditionBmi2AdxX255
		x448.ladderStep = ladderStepBmi2AdxX448
		x448.double = doubleBmi2AdxX448
		x448.difadd = difAdditionBmi2AdxX448
	} else {
		x255.ladderStep = ladderStepLegX255
		x255.double = doubleLegX255
		x255.difadd = difAdditionLegX255
		x448.ladderStep = ladderStepLegX448
		x448.double = doubleLegX448
		x448.difadd = difAdditionLegX448
	}
}

// This workspace contains four field elements and two bigElements for
// evaluating a Joye's ladder step.
// struct {
//     x1, z1, x2, z2 field.Element
//     buffer         [2]field.bigElement
// }
// Attention: The order of fields [x1,z1,x2,z2,buffer] must be preserved
func (c *xcurve) initWorkJoye() []byte {
	w := make([]byte, (4+2*2)*c.size)
	n := c.size
	copy(w[0*n:1*n], c.pointS)  // x1 = S
	copy(w[2*n:3*n], c.pointGS) // x2 = G-S
	w[1*n] = 1                  // z1 = 1
	w[3*n] = 1                  // z2 = 1
	return w
}

// This workspace contains seven field elements and two bigElements for
// evaluating a Montgomery's ladder step.
// struct {
//     x1, x2, z2, x3, z3, t0, t1 field.Element
// 	   buffer                     [2]field.bigElement
// }
// Attention: The order of fields [x1,x2,z2,x3,z3,t0,t1,buffer] must be preserved
func (c *xcurve) initWorkMont(xP []byte) []byte {
	w := make([]byte, (7+2*2)*c.size)
	n := c.size
	copy(w[0*n:1*n], xP) // x1 = xP
	copy(w[3*n:4*n], xP) // x3 = xP
	w[1*n] = 1           // x2 = 1
	w[4*n] = 1           // z3 = 1
	return w
}

// ladderJoye calculates a scalar point multiplication using generator point
// The algorithm implemented is the right-to-left Joye's ladder as described
// in "How to precompute a ladder" in SAC'2017.
func (c *xcurve) ladderJoye(k []byte) []byte {
	w := c.initWorkJoye()
	swap := uint(1)
	for s := 0; s < c.n-c.h; s++ {
		i := (s + c.h) / 8
		j := (s + c.h) % 8
		bit := uint((k[i] >> uint(j)) & 1)
		mu := c.table[s*c.size : (s+1)*c.size]
		c.difadd(w, mu, swap^bit)
		swap = bit
	}
	for s := 0; s < c.h; s++ {
		c.double(w)
	}
	n := c.size
	return c.toAffine(w[0*n:1*n], w[1*n:2*n])
}

// ladderMontgomery calculates a generic scalar point multiplication
// The algorithm implemented is the left-to-right Montgomery's ladder
func (c *xcurve) ladderMontgomery(k []byte, xP []byte) []byte {
	w := c.initWorkMont(xP)
	move := uint(0)
	for s := c.n - 1; s >= 0; s-- {
		i := s / 8
		j := s % 8
		bit := uint((k[i] >> uint(j)) & 1)
		c.ladderStep(w, move^bit)
		move = bit
	}
	n := c.size
	return c.toAffine(w[1*n:2*n], w[2*n:3*n])
}

//Functions defined in assembler files.

//go:noescape
func ladderStepLegX255(wbuf []byte, move uint)

//go:noescape
func ladderStepBmi2AdxX255(wbuf []byte, move uint)

//go:noescape
func difAdditionLegX255(wbuf []byte, mu []byte, swap uint)

//go:noescape
func difAdditionBmi2AdxX255(wbuf []byte, mu []byte, swap uint)

//go:noescape
func doubleBmi2AdxX255(wbuf []byte)

//go:noescape
func doubleLegX255(wbuf []byte)

//go:noescape
func ladderStepLegX448(wbuf []byte, move uint)

//go:noescape
func ladderStepBmi2AdxX448(wbuf []byte, move uint)

//go:noescape
func difAdditionLegX448(wbuf []byte, mu []byte, swap uint)

//go:noescape
func difAdditionBmi2AdxX448(wbuf []byte, mu []byte, swap uint)

//go:noescape
func doubleBmi2AdxX448(wbuf []byte)

//go:noescape
func doubleLegX448(wbuf []byte)
