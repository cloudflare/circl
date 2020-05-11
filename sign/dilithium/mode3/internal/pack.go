package internal

import (
	common "github.com/cloudflare/circl/sign/dilithium/internal"
)

// Writes p with norm less than or equal η into buf, which must be of
// size PolyLeqEtaSize.
//
// Assumes coefficients of p are not normalized, but in [q-η,q+η].
func PolyPackLeqEta(p *common.Poly, buf []byte) {
	if DoubleEtaBits == 4 { // compiler eliminates branch
		j := 0
		for i := 0; i < PolyLeqEtaSize; i++ {
			buf[i] = (byte(common.Q+Eta-p[j]) |
				byte(common.Q+Eta-p[j+1])<<4)
			j += 2
		}
	} else if DoubleEtaBits == 3 {
		j := 0
		for i := 0; i < PolyLeqEtaSize; i += 3 {
			buf[i] = (byte(common.Q+Eta-p[j]) |
				(byte(common.Q+Eta-p[j+1]) << 3) |
				(byte(common.Q+Eta-p[j+2]) << 6))
			buf[i+1] = ((byte(common.Q+Eta-p[j+2]) >> 2) |
				(byte(common.Q+Eta-p[j+3]) << 1) |
				(byte(common.Q+Eta-p[j+4]) << 4) |
				(byte(common.Q+Eta-p[j+5]) << 7))
			buf[i+2] = ((byte(common.Q+Eta-p[j+5]) >> 1) |
				(byte(common.Q+Eta-p[j+6]) << 2) |
				(byte(common.Q+Eta-p[j+7]) << 5))
			j += 8
		}
	} else {
		panic("eta not supported")
	}
}

// Sets p to the polynomial of norm less than or equal η encoded in the
// given buffer of size PolyLeqEtaSize.
//
// Output coefficients of p are not normalized, but in [q-η,q+η] provided
// buf was created using PackLeqEta.
//
// Beware, for arbitrary buf the coefficients of p might en up in
// the interval [q-2^b,q+2^b] where b is the least b with η≤2^b.
func PolyUnpackLeqEta(p *common.Poly, buf []byte) {
	if DoubleEtaBits == 4 { // compiler eliminates branch
		j := 0
		for i := 0; i < PolyLeqEtaSize; i++ {
			p[j] = common.Q + Eta - uint32(buf[i]&15)
			p[j+1] = common.Q + Eta - uint32(buf[i]>>4)
			j += 2
		}
	} else if DoubleEtaBits == 3 {
		j := 0
		for i := 0; i < PolyLeqEtaSize; i += 3 {
			p[j] = common.Q + Eta - uint32(buf[i]&7)
			p[j+1] = common.Q + Eta - uint32((buf[i]>>3)&7)
			p[j+2] = common.Q + Eta - uint32((buf[i]>>6)|((buf[i+1]<<2)&7))
			p[j+3] = common.Q + Eta - uint32((buf[i+1]>>1)&7)
			p[j+4] = common.Q + Eta - uint32((buf[i+1]>>4)&7)
			p[j+5] = common.Q + Eta - uint32((buf[i+1]>>7)|((buf[i+2]<<1)&7))
			p[j+6] = common.Q + Eta - uint32((buf[i+2]>>2)&7)
			p[j+7] = common.Q + Eta - uint32((buf[i+2]>>5)&7)
			j += 8
		}
	} else {
		panic("eta not supported")
	}
}

// Writes v with coefficients in {0, 1} of which at most ω non-zero
// to buf, which must have length ω+k.
func (v *VecK) PackHint(buf []byte) {
	// The packed hint starts with the indices of the non-zero coefficients
	// For instance:
	//
	//    (x⁵⁶ + x¹⁰⁰, x²⁵⁵, 0, x² + x²³, x¹)
	//
	// Yields
	//
	//  56, 100, 255, 2, 23, 1
	//
	// Then we pad with zeroes until we have a list of ω items:
	// //  56, 100, 255, 2, 23, 1, 0, 0, ..., 0
	//
	// Then we finish with a list of the switch-over-indices in this
	// list between polynomials, so:
	//
	//  56, 100, 255, 2, 23, 1, 0, 0, ..., 0, 2, 3, 3, 5, 6

	off := uint8(0)
	for i := 0; i < K; i++ {
		for j := uint16(0); j < common.N; j++ {
			if v[i][j] != 0 {
				buf[off] = uint8(j)
				off++
			}
		}
		buf[Omega+i] = off
	}
	for ; off < Omega; off++ {
		buf[off] = 0
	}
}

// Sets v to the vector encoded using VecK.PackHint()
//
// Returns whether unpacking was successful.
func (v *VecK) UnpackHint(buf []byte) bool {
	// A priori, there would be several reasonable ways to encode the same
	// hint vector.  We take care to only allow only one encoding, to ensure
	// "strong unforgeability".
	//
	// See PackHint() source for description of the encoding.
	*v = VecK{}         // zero v
	prevSOP := uint8(0) // previous switch-over-point
	for i := 0; i < K; i++ {
		SOP := buf[Omega+i]
		if SOP < prevSOP || SOP > Omega {
			return false // ensures switch-over-points are increasing
		}
		for j := prevSOP; j < SOP; j++ {
			if j > prevSOP && buf[j] <= buf[j-1] {
				return false // ensures indices are increasing (within a poly)
			}
			v[i][buf[j]] = 1
		}
		prevSOP = SOP
	}
	for j := prevSOP; j < Omega; j++ {
		if buf[j] != 0 {
			return false // ensures padding indices are zero
		}
	}

	return true
}
