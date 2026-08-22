package internal

import (
	common "github.com/cloudflare/circl/sign/internal/dilithium"
)

// A k by l matrix of polynomials.
type Mat [K]VecL

// Expands the given seed to a complete matrix.
//
// This function is called ExpandA in the specification.
func (m *Mat) Derive(seed *[32]byte) {
	if DeriveX4Available {
		m.deriveX4(seed)
		return
	}

	if DeriveX2Available {
		m.deriveX2(seed)
		return
	}

	for i := uint16(0); i < K; i++ {
		for j := uint16(0); j < L; j++ {
			PolyDeriveUniform(&m[i][j], seed, (i<<8)+j)
		}
	}
}

// Expands the given seed to a complete matrix, four polynomials at a time.
//
// Can only be called when DeriveX4Available is true.
func (m *Mat) deriveX4(seed *[32]byte) {
	idx := 0
	var nonces [4]uint16
	var ps [4]*common.Poly
	for i := uint16(0); i < K; i++ {
		for j := uint16(0); j < L; j++ {
			nonces[idx] = (i << 8) + j
			ps[idx] = &m[i][j]
			idx++
			if idx == 4 {
				idx = 0
				PolyDeriveUniformX4(ps, seed, nonces)
			}
		}
	}
	if idx != 0 {
		for i := idx; i < 4; i++ {
			ps[i] = nil
		}
		PolyDeriveUniformX4(ps, seed, nonces)
	}
}

// Expands the given seed to a complete matrix, two polynomials at a time.
//
// Can only be called when DeriveX2Available is true.
func (m *Mat) deriveX2(seed *[32]byte) {
	idx := 0
	var nonces [2]uint16
	var ps [2]*common.Poly
	for i := uint16(0); i < K; i++ {
		for j := uint16(0); j < L; j++ {
			nonces[idx] = (i << 8) + j
			ps[idx] = &m[i][j]
			idx++
			if idx == 2 {
				idx = 0
				PolyDeriveUniformX2(ps, seed, nonces)
			}
		}
	}
	if idx != 0 {
		for i := idx; i < 2; i++ {
			ps[i] = nil
		}
		PolyDeriveUniformX2(ps, seed, nonces)
	}
}

// Set p to the inner product of a and b using pointwise multiplication.
//
// Assumes a and b are in Montgomery form and their coefficients are
// pairwise sufficiently small to multiply, see Poly.MulHat().  Resulting
// coefficients are bounded by 2Lq.
func PolyDotHat(p *common.Poly, a, b *VecL) {
	var t common.Poly
	*p = common.Poly{} // zero p
	for i := 0; i < L; i++ {
		t.MulHat(&a[i], &b[i])
		p.Add(&t, p)
	}
}
