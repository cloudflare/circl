// +build amd64

package x448

import (
	"golang.org/x/sys/cpu"

	"github.com/cloudflare/circl/math/fp448"
)

var hasBmi2Adx = cpu.X86.HasBMI2 && cpu.X86.HasADX

func (c *curve) ladderStep(w *[5]fp448.Elt, b uint) { ladderStep448(w, b) }

func (c *curve) mulA24(z, x *fp448.Elt) { mulA24448(z, x) }

func (c *curve) double(x, z *fp448.Elt) { double448(x, z) }

func (c *curve) difAdd(w *[5]fp448.Elt, b uint) { difAdd448(w, b) }

// ladderStep448 calculates a point addition and doubling as follows:
// (x2,z2) = 2*(x2,z2) and (x3,z3) = (x2,z2)+(x3,z3) using as a difference (x1,-).
//   work  = {x1,x2,z2,x3,z3} are five fp448.Elt of 56 bytes.
//go:noescape
func ladderStep448(w *[5]fp448.Elt, b uint)

// diffAdd448 calculates a differential point addition using a precomputed point.
// (x1,z1) = (x1,z1)+(mu) using a difference point (x2,z2)
// work = {mu,x1,z1,x2,z2} are five fp448.Elt of 56 bytes.
// See Equation 7 at https://eprint.iacr.org/2017/264.
//go:noescape
func difAdd448(w *[5]fp448.Elt, b uint)

// double448 calculates a point doubling (x1,z1) = 2*(x1,z1).
//go:noescape
func double448(x, z *fp448.Elt)

//go:noescape
func mulA24448(z, x *fp448.Elt)
