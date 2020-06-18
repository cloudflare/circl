package common

import (
	"encoding/binary"
)

// Sets p to the polynomial whose coefficients are less than 512 encoded
// into buf (which must be of size PolyT1Size).
//
// p will be normalized.
func (p *Poly) UnpackT1(buf []byte) {
	j := 0
	for i := 0; i < PolyT1Size; i += 9 {
		p[j] = (uint32(buf[i]) | (uint32(buf[i+1]) << 8)) & 0x1ff
		p[j+1] = (uint32(buf[i+1]>>1) | (uint32(buf[i+2]) << 7)) & 0x1ff
		p[j+2] = (uint32(buf[i+2]>>2) | (uint32(buf[i+3]) << 6)) & 0x1ff
		p[j+3] = (uint32(buf[i+3]>>3) | (uint32(buf[i+4]) << 5)) & 0x1ff
		p[j+4] = (uint32(buf[i+4]>>4) | (uint32(buf[i+5]) << 4)) & 0x1ff
		p[j+5] = (uint32(buf[i+5]>>5) | (uint32(buf[i+6]) << 3)) & 0x1ff
		p[j+6] = (uint32(buf[i+6]>>6) | (uint32(buf[i+7]) << 2)) & 0x1ff
		p[j+7] = (uint32(buf[i+7]>>7) | (uint32(buf[i+8]) << 1)) & 0x1ff
		j += 8
	}
}

// Writes p whose coefficients are in (-2ᵈ⁻¹, 2ᵈ⁻¹] into buf which
// has to be of length at least PolyT0Size.
//
// Assumes that the coefficients are not normalized, but lie in the
// range (q-2ᵈ⁻¹, q+2ᵈ⁻¹].
func (p *Poly) PackT0(buf []byte) {
	j := 0
	for i := 0; i < PolyT0Size; i += 7 {
		p0 := Q + (1 << (D - 1)) - p[j]
		p1 := Q + (1 << (D - 1)) - p[j+1]
		p2 := Q + (1 << (D - 1)) - p[j+2]
		p3 := Q + (1 << (D - 1)) - p[j+3]

		buf[i] = byte(p0)
		buf[i+1] = byte(p0>>8) | byte(p1<<6)
		buf[i+2] = byte(p1 >> 2)
		buf[i+3] = byte(p1>>10) | byte(p2<<4)
		buf[i+4] = byte(p2 >> 4)
		buf[i+5] = byte(p2>>12) | byte(p3<<2)
		buf[i+6] = byte(p3 >> 6)
		j += 4
	}
}

// Sets p to the polynomial packed into buf by PackT0.
//
// The coefficients of p will not be normalized, but will lie
// in (-2ᵈ⁻¹, 2ᵈ⁻¹].
func (p *Poly) UnpackT0(buf []byte) {
	j := 0
	for i := 0; i < PolyT0Size; i += 7 {
		p[j] = Q + (1 << (D - 1)) - ((uint32(buf[i]) |
			(uint32(buf[i+1]) << 8)) & 0x3fff)
		p[j+1] = Q + (1 << (D - 1)) - (((uint32(buf[i+1]) >> 6) |
			(uint32(buf[i+2]) << 2) |
			(uint32(buf[i+3]) << 10)) & 0x3fff)
		p[j+2] = Q + (1 << (D - 1)) - (((uint32(buf[i+3]) >> 4) |
			(uint32(buf[i+4]) << 4) |
			(uint32(buf[i+5]) << 12)) & 0x3fff)
		p[j+3] = Q + (1 << (D - 1)) - ((uint32(buf[i+5]) >> 2) |
			(uint32(buf[i+6]) << 6))
		j += 4
	}
}

// Writes p whose coefficients are less than 512 into buf, which must be
// of size at least PolyT1Size .
//
// Assumes coefficients of p are normalized.
func (p *Poly) PackT1(buf []byte) {
	j := 0
	for i := 0; i < PolyT1Size; i += 9 {
		buf[i] = byte(p[j])
		buf[i+1] = byte(p[j]>>8) | byte(p[j+1]<<1)
		buf[i+2] = byte(p[j+1]>>7) | byte(p[j+2]<<2)
		buf[i+3] = byte(p[j+2]>>6) | byte(p[j+3]<<3)
		buf[i+4] = byte(p[j+3]>>5) | byte(p[j+4]<<4)
		buf[i+5] = byte(p[j+4]>>4) | byte(p[j+5]<<5)
		buf[i+6] = byte(p[j+5]>>3) | byte(p[j+6]<<6)
		buf[i+7] = byte(p[j+6]>>2) | byte(p[j+7]<<7)
		buf[i+8] = byte(p[j+7] >> 1)
		j += 8
	}
}

// Writes p whose coefficients are in norm less than γ₁ into buf
// which has to be of length PolyLeGamma1Size.
//
// Assumes p is normalized.
func (p *Poly) PackLeGamma1(buf []byte) {
	j := 0
	for i := 0; i < PolyLeGamma1Size; i += 5 {
		// Coefficients are in [0, γ₁) ∪ (Q-γ₁, Q)
		p0 := Gamma1 - 1 - p[j]         // ... in [0, γ₁) ∪ [γ₁-1-Q, 2(γ₁-1)-Q]
		p0 += uint32(int32(p0)>>31) & Q // ... in [0, 2(γ₁-1)]
		p1 := Gamma1 - 1 - p[j+1]
		p1 += uint32(int32(p1)>>31) & Q

		buf[i] = byte(p0)
		buf[i+1] = byte(p0 >> 8)
		buf[i+2] = byte(p0>>16) | byte(p1<<4)
		buf[i+3] = byte(p1 >> 4)
		buf[i+4] = byte(p1 >> 12)
		j += 2
	}
}

// Sets p to the polynomial packed into buf by PackLeGamma1.
//
// p will be normalized.
//
// Beware, for arbitrary buf the coefficients of p might exceed γ₁.
func (p *Poly) UnpackLeGamma1(buf []byte) {
	j := 0
	for i := 0; i < PolyLeGamma1Size; i += 40 {
		a0 := binary.LittleEndian.Uint64(buf[i:])
		a1 := binary.LittleEndian.Uint64(buf[i+8:])
		a2 := binary.LittleEndian.Uint64(buf[i+16:])
		a3 := binary.LittleEndian.Uint64(buf[i+24:])
		a4 := binary.LittleEndian.Uint64(buf[i+32:])

		p0 := Gamma1 - 1 - uint32(a0&0xfffff)
		p1 := Gamma1 - 1 - uint32((a0>>20)&0xfffff)
		p2 := Gamma1 - 1 - uint32((a0>>40)&0xfffff)
		p3 := Gamma1 - 1 - uint32(((a0>>60)|(a1<<4))&0xfffff)
		p4 := Gamma1 - 1 - uint32((a1>>16)&0xfffff)
		p5 := Gamma1 - 1 - uint32((a1>>36)&0xfffff)
		p6 := Gamma1 - 1 - uint32(((a1>>56)|(a2<<8))&0xfffff)
		p7 := Gamma1 - 1 - uint32((a2>>12)&0xfffff)
		p8 := Gamma1 - 1 - uint32((a2>>32)&0xfffff)
		p9 := Gamma1 - 1 - uint32(((a2>>52)|(a3<<12))&0xfffff)
		p10 := Gamma1 - 1 - uint32((a3>>8)&0xfffff)
		p11 := Gamma1 - 1 - uint32((a3>>28)&0xfffff)
		p12 := Gamma1 - 1 - uint32(((a3>>48)|(a4<<16))&0xfffff)
		p13 := Gamma1 - 1 - uint32((a4>>4)&0xfffff)
		p14 := Gamma1 - 1 - uint32((a4>>24)&0xfffff)
		p15 := Gamma1 - 1 - uint32((a4>>44)&0xfffff)

		p0 += uint32(int32(p0)>>31) & Q
		p1 += uint32(int32(p1)>>31) & Q
		p2 += uint32(int32(p2)>>31) & Q
		p3 += uint32(int32(p3)>>31) & Q
		p4 += uint32(int32(p4)>>31) & Q
		p5 += uint32(int32(p5)>>31) & Q
		p6 += uint32(int32(p6)>>31) & Q
		p7 += uint32(int32(p7)>>31) & Q
		p8 += uint32(int32(p8)>>31) & Q
		p9 += uint32(int32(p9)>>31) & Q
		p10 += uint32(int32(p10)>>31) & Q
		p11 += uint32(int32(p11)>>31) & Q
		p12 += uint32(int32(p12)>>31) & Q
		p13 += uint32(int32(p13)>>31) & Q
		p14 += uint32(int32(p14)>>31) & Q
		p15 += uint32(int32(p15)>>31) & Q

		p[j] = p0
		p[j+1] = p1
		p[j+2] = p2
		p[j+3] = p3
		p[j+4] = p4
		p[j+5] = p5
		p[j+6] = p6
		p[j+7] = p7
		p[j+8] = p8
		p[j+9] = p9
		p[j+10] = p10
		p[j+11] = p11
		p[j+12] = p12
		p[j+13] = p13
		p[j+14] = p14
		p[j+15] = p15

		j += 16
	}
}

// Writes p whose coefficients are in [0, 16) to buf, which must be of
// length N/2.
func (p *Poly) packLe16Generic(buf []byte) {
	j := 0
	for i := 0; i < PolyLe16Size; i++ {
		buf[i] = byte(p[j]) | byte(p[j+1]<<4)
		j += 2
	}
}

// Writes p with 60 non-zero coefficients {-1,1} to buf, which must have
// length 40.
func (p *Poly) PackB60(buf []byte) {
	// We start with a mask of the non-zero positions of p (which is 32 bytes)
	// and then append 60 packed bits, where a one indicates a negative
	// coefficients.
	var signs uint64
	mask := uint64(1)
	for i := 0; i < 32; i++ {
		buf[i] = 0
		for j := 0; j < 8; j++ {
			if p[8*i+j] != 0 {
				buf[i] |= 1 << uint(j)
				if p[8*i+j] == Q-1 {
					signs |= mask
				}
				mask <<= 1
			}
		}
	}
	for i := uint64(0); i < 8; i++ {
		buf[i+32] = uint8(signs >> (8 * i))
	}
}

// UnpackB60 sets p to the polynomial packed into buf with Poly.PackB60().
//
// Returns whether unpacking was successful.
func (p *Poly) UnpackB60(buf []byte) bool {
	*p = Poly{} // zero p
	signs := (uint64(buf[32]) | (uint64(buf[33]) << 8) |
		(uint64(buf[34]) << 16) | (uint64(buf[35]) << 24) |
		(uint64(buf[36]) << 32) | (uint64(buf[37]) << 40) |
		(uint64(buf[38]) << 48) | (uint64(buf[39]) << 56))
	if signs>>60 != 0 {
		return false // ensure unused bits are zero for strong unforgeability
	}

	for i := 0; i < 32; i++ {
		for j := 0; j < 8; j++ {
			if (buf[i]>>uint(j))&1 == 1 {
				p[8*i+j] = 1
				// Note 1 ^ (1 | (Q-1)) = Q-1 and (-1)&x = x
				p[8*i+j] ^= uint32(-(signs & 1)) & (1 | (Q - 1))
				signs >>= 1
			}
		}
	}

	return true
}
