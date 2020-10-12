// +build amd64

package common

import (
	"golang.org/x/sys/cpu"
)

// Sets p to a + b.  Does not normalize coefficients.
func (p *Poly) Add(a, b *Poly) {
    if cpu.X86.HasAVX2 {
        addAVX2(
            (*[N]int16)(p),
            (*[N]int16)(a),
            (*[N]int16)(b),
        )
    } else {
        p.addGeneric(a, b)
    }
}

// Sets p to a - b.  Does not normalize coefficients.
func (p *Poly) Sub(a, b *Poly) {
    if cpu.X86.HasAVX2 {
        subAVX2(
            (*[N]int16)(p),
            (*[N]int16)(a),
            (*[N]int16)(b),
        )
    } else {
        p.subGeneric(a, b)
    }
}
