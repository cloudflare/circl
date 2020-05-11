package internal

import (
	"github.com/cloudflare/circl/internal/shake"
	common "github.com/cloudflare/circl/sign/dilithium/internal"
)

// Sample p uniformly from the given seed and nonce.
//
// p will be normalized.
func PolyDeriveUniform(p *common.Poly, seed *[32]byte, nonce uint16) {
	var i, length int
	var buf [12 * 16]byte // fits 168B SHAKE-128 rate and 12 16B AES blocks

	if UseAES {
		length = 12 * 16
	} else {
		length = 168
	}

	sample := func() {
		// Note that 3 divides into 168 and 12*16, so we use up buf completely.
		for j := 0; j < length && i < common.N; j += 3 {
			t := (uint32(buf[j]) | (uint32(buf[j+1]) << 8) |
				(uint32(buf[j+2]) << 16)) & 0x7fffff

			// We use rejection sampling
			if t < common.Q {
				p[i] = t
				i++
			}
		}
	}

	if UseAES {
		h := common.NewAesStream128(seed, nonce)

		for i < common.N {
			h.SqueezeInto(buf[:length])
			sample()
		}
	} else {
		var iv [32 + 2]byte // 32 byte seed + uint16 nonce
		h := shake.NewShake128()
		copy(iv[:32], seed[:])
		iv[32] = uint8(nonce)
		iv[33] = uint8(nonce >> 8)
		_, _ = h.Write(iv[:])

		for i < common.N {
			_, _ = h.Read(buf[:168])
			sample()
		}
	}
}

// Sample p uniformly with coefficients of norm less than or equal η,
// using the given seed and nonce.
//
// p will not be normalized, but will have coefficients in [q-η,q+η].
func PolyDeriveUniformLeqEta(p *common.Poly, seed *[32]byte, nonce uint16) {
	// Assumes 2 < η < 8.
	var i, length int
	var buf [11 * 16]byte // fits 168B SHAKE-128 rate and 11 16B AES blocks

	if UseAES {
		length = 11 * 16
	} else {
		length = 168
	}

	sample := func() {
		// We use rejection sampling
		for j := 0; j < length && i < common.N; j++ {
			var t1, t2 uint32
			if Eta <= 3 { // branch is eliminated by compiler
				t1 = uint32(buf[j]) & 7
				t2 = uint32(buf[j]) >> 5
			} else {
				t1 = uint32(buf[j]) & 15
				t2 = uint32(buf[j]) >> 4
			}
			if t1 <= 2*Eta {
				p[i] = common.Q + Eta - t1
				i++
			}
			if t2 <= 2*Eta && i < common.N {
				p[i] = common.Q + Eta - t2
				i++
			}
		}
	}

	if UseAES {
		h := common.NewAesStream128(seed, nonce)

		for i < common.N {
			h.SqueezeInto(buf[:length])
			sample()
		}
	} else {
		var iv [32 + 2]byte // 32 byte seed + uint16 nonce

		h := shake.NewShake128()
		copy(iv[:32], seed[:])
		iv[32] = uint8(nonce)
		iv[33] = uint8(nonce >> 8)

		// 168 is SHAKE-128 rate
		_, _ = h.Write(iv[:])

		for i < common.N {
			_, _ = h.Read(buf[:168])
			sample()
		}
	}
}

// Sample v[i] uniformly with coefficients of norm less than γ₁ using the
// given seed and nonce+i
//
// v[i] will not be normalized, but have coefficients in the
// interval (q-γ₁,q+γ₁).
func VecLDeriveUniformLeGamma1(v *VecL, seed *[48]byte, nonce uint16) {
	for i := 0; i < L; i++ {
		PolyDeriveUniformLeGamma1(&v[i], seed, nonce+uint16(i))
	}
}

// Sample p uniformly with coefficients of norm less than γ₁ using the
// given seed and nonce.
//
// p will not be normalized, but have coefficients in the
// interval (q-γ₁,q+γ₁).
func PolyDeriveUniformLeGamma1(p *common.Poly, seed *[48]byte, nonce uint16) {
	// Assumes γ1 is less than 2²⁰.
	var length, i int

	// Fits 10 16B AES blocks, which aligns nicely as we take 5 bytes at
	// a time.  The SHAKE-256 rate, however, is 136.  As 136 is 1 modulo 5,
	// we are left with 1 byte after the first block, which we include in the
	// next block.  So we need 4 bytes leeway in our buffer.  The total 160
	// fits easily in 160.
	var buf [160]byte

	sample := func() {
		// We use rejection sampling
		for j := 0; j < length-4 && i < common.N; j += 5 {
			t1 := (uint32(buf[j]) | (uint32(buf[j+1]) << 8) |
				(uint32(buf[j+2]) << 16)) & 0xfffff
			t2 := ((uint32(buf[j+2]) >> 4) | (uint32(buf[j+3]) << 4) |
				(uint32(buf[j+4]) << 12))

			if t1 <= 2*common.Gamma1-2 {
				p[i] = common.Q + common.Gamma1 - 1 - t1
				i++
			}
			if t2 <= 2*common.Gamma1-2 && i < common.N {
				p[i] = common.Q + common.Gamma1 - 1 - t2
				i++
			}
		}
	}
	if UseAES {
		length = 160
		h := common.NewAesStream256(seed, nonce)

		for i < common.N {
			h.SqueezeInto(buf[:])
			sample()
		}
	} else {
		length = 136
		var iv [48 + 2]byte // 48 byte seed + uint16 nonce
		bufOffset := 0      // where to put the next block

		h := shake.NewShake256()
		copy(iv[:48], seed[:])
		iv[48] = uint8(nonce)
		iv[49] = uint8(nonce >> 8)
		_, _ = h.Write(iv[:])

		for i < common.N {
			_, _ = h.Read(buf[bufOffset : bufOffset+136])
			sample()

			bufOffset++
			if bufOffset == 5 {
				bufOffset = 0
			}

			// Move remaining bytes at the end to the start.
			for j := 0; j < bufOffset; j++ {
				buf[j] = buf[135+j]
			}
		}
	}
}

// Samples p uniformly with 60 non-zero coefficients in {q-1,1}.
//
// The polynomial p will be normalized.
func PolyDeriveUniformB60(p *common.Poly, seed *[48]byte, w1 *VecK) {
	var w1Packed [common.PolyLe16Size * K]byte
	var buf [136]byte // SHAKE-256 rate is 136

	w1.PackLe16(w1Packed[:])

	h := shake.NewShake256()
	_, _ = h.Write(seed[:])
	_, _ = h.Write(w1Packed[:])
	_, _ = h.Read(buf[:])

	// Essentially we generate a sequence of 60 ones or minus ones,
	// prepend 196 zeroes and shuffle the concatenation using the
	// usual algorithm (Fisher--Yates.)
	signs := (uint64(buf[0]) | (uint64(buf[1]) << 8) | (uint64(buf[2]) << 16) |
		(uint64(buf[3]) << 24) | (uint64(buf[4]) << 32) | (uint64(buf[5]) << 40) |
		(uint64(buf[6]) << 48) | (uint64(buf[7]) << 56))
	bufOff := 8 // offset into buf

	*p = common.Poly{} // zero p
	for i := uint16(256 - 60); i < 256; i++ {
		var b uint16

		// Find location of where to move the new coefficient to using
		// rejection sampling.
		for {
			if bufOff >= 136 {
				_, _ = h.Read(buf[:])
				bufOff = 0
			}

			b = uint16(buf[bufOff])
			bufOff++

			if b <= i {
				break
			}
		}

		p[i] = p[b]
		p[b] = 1
		// Takes least significant bit of signs and uses it for the sign.
		// Note 1 ^ (1 | (Q-1)) = Q-1.
		p[b] ^= uint32((-(signs & 1)) & (1 | (common.Q - 1)))
		signs >>= 1
	}
}
