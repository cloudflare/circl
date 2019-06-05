// +build amd64

package x25519

import (
	"golang.org/x/sys/cpu"

	fp255 "github.com/cloudflare/circl/math/fp25519"
)

var hasBmi2Adx = cpu.X86.HasBMI2 && cpu.X86.HasADX

func (c *curve) ladderStep(w *[5]fp255.Elt, b uint) { ladderStep255(w, b) }

func (c *curve) mulA24(z, x *fp255.Elt) { mulA24255(z, x) }

func (c *curve) double(x, z *fp255.Elt) { double255(x, z) }

func (c *curve) difAdd(w *[5]fp255.Elt, b uint) { difAdd255(w, b) }

// ladderStep255 calculates a point addition and doubling as follows:
// (x2,z2) = 2*(x2,z2) and (x3,z3) = (x2,z2)+(x3,z3) using as a difference (x1,-).
//   work  = {x1,x2,z2,x3,z3} are five fp255.Elt of 32 bytes.
//go:noescape
func ladderStep255(w *[5]fp255.Elt, b uint)

// diffAdd255 calculates a differential point addition using a precomputed point.
// (x1,z1) = (x1,z1)+(mu) using a difference point (x2,z2)
//    work = {mu,x1,z1,x2,z2} are five fp.Elt of fp.Size bytes.
// See Equation 7 at https://eprint.iacr.org/2017/264.
//go:noescape
func difAdd255(w *[5]fp255.Elt, b uint)

// double255 calculates a point doubling (x1,z1) = 2*(x1,z1).
//go:noescape
func double255(x, z *fp255.Elt)

//go:noescape
func mulA24255(z, x *fp255.Elt)
