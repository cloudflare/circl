//go:generate go run ntt_amd64_src.go -out ntt_amd64.s -stubs ntt_amd64_stubs.go

package internal

import (
	"golang.org/x/sys/cpu"
)

// Execute an in-place forward NTT on as.
//
// Assumes the coefficients are in Montgomery representation and bounded
// by 2*Q.  The resulting coefficients are again in Montgomery representation,
// but are only bounded bt 18*Q.
func (p *Poly) NTT() {
	if cpu.X86.HasAVX2 {
		nttAVX2(
			(*[N]uint32)(p),
		)
	} else {
		p.nttGeneric()
	}
}

// Execute an in-place inverse NTT and multiply by Montgomery factor R
//
// Assumes the coefficients are in Montgomery representation and bounded
// by 2*Q.  The resulting coefficients are again in Montgomery representation
// and bounded by 2*Q.
func (p *Poly) InvNTT() {
	if cpu.X86.HasAVX2 {
		invNttAVX2(
			(*[N]uint32)(p),
		)
	} else {
		p.invNttGeneric()
	}
}

// Sets p to the polynomial whose coefficients are the pointwise multiplication
// of those of a and b.  The coefficients of p are bounded by 2q.
//
// Assumes a and b are in Montgomery form and that the pointwise product
// of each coefficient is below 2^32 q.
func (p *Poly) MulHat(a, b *Poly) {
	if cpu.X86.HasAVX2 {
		mulHatAVX2(
			(*[N]uint32)(p),
			(*[N]uint32)(a),
			(*[N]uint32)(b),
		)
	} else {
		p.mulHatGeneric(a, b)
	}
}

// Sets p to a + b.  Does not normalize polynomials.
func (p *Poly) Add(a, b *Poly) {
	if cpu.X86.HasAVX2 {
		addAVX2(
			(*[N]uint32)(p),
			(*[N]uint32)(a),
			(*[N]uint32)(b),
		)
	} else {
		p.addGeneric(a, b)
	}
}

// Sets p to a - b.
//
// Warning: assumes coefficients of b are less than 2q.
// Sets p to a + b.  Does not normalize polynomials.
func (p *Poly) Sub(a, b *Poly) {
	if cpu.X86.HasAVX2 {
		subAVX2(
			(*[N]uint32)(p),
			(*[N]uint32)(a),
			(*[N]uint32)(b),
		)
	} else {
		p.subGeneric(a, b)
	}
}

// Writes p whose coefficients are in [0, 16) to buf, which must be of
// length N/2.
func (p *Poly) PackLe16(buf []byte) {
	if cpu.X86.HasAVX2 {
		if len(buf) < PolyLe16Size {
			panic("buf too small")
		}
		packLe16AVX2(
			(*[N]uint32)(p),
			&buf[0],
		)
	} else {
		p.packLe16Generic(buf)
	}
}
