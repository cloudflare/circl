// +build amd64,go1.12

package fourQ

import (
	"golang.org/x/sys/cpu"
)

var hasBMI2 = cpu.X86.HasBMI2

var _ = hasBMI2

//go:noescape
func fpMod(c *Fp)

//go:noescape
func fpAdd(c, a, b *Fp)

//go:noescape
func fpSub(c, a, b *Fp)

//go:noescape
func fpMul(c, a, b *Fp)

//go:noescape
func fpSqr(c, a *Fp)

//go:noescape
func fpHlf(c, a *Fp)
