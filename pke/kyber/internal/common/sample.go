package common

import (
	"github.com/cloudflare/circl/internal/shake"

	"encoding/binary"
)

// Samples p from a centered binomial distribution with given η.
//
// Essentially CBD_η(PRF(seed, nonce)) from the specification.
func (p *Poly) DeriveNoise(seed []byte, nonce uint8, eta int) {
	switch eta {
	case 2:
		p.DeriveNoise2(seed, nonce)
	case 3:
		p.DeriveNoise3(seed, nonce)
	default:
		panic("unsupported eta")
	}
}

// Sample p from a centered binomial distribution with n=6 and p=½ - that is:
// coefficients are in {-3, -2, -1, 0, 1, 2, 3} with probabilities {1/64, 3/32,
// 15/64, 5/16, 16/64, 3/32, 1/64}.
func (p *Poly) DeriveNoise3(seed []byte, nonce uint8) {
	keySuffix := [1]byte{nonce}
	h := shake.NewShake256()
	_, _ = h.Write(seed[:])
	_, _ = h.Write(keySuffix[:])

	// The distribution at hand is exactly the same as that
	// of (a₁ + a₂ + a₃) - (b₁ + b₂+b₃) where a_i,b_i~U(1).  Thus we need
	// 6 bits per coefficients, thus 192 bytes of input entropy.

	// We add one extra zero byte in the buffer to be able to read 4 bytes
	// at the same time (while using only 3.)
	var buf [192 + 1]byte
	_, _ = h.Read(buf[:192])

	// XXX 64 bits at a time?
	for i := 0; i < 64; i++ {
		// t is interpreted as a₁ + 2a₂ + 4a₃ + 8b₁ + 16b₂ + ….
		t := binary.LittleEndian.Uint32(buf[3*i:])

		d := t & 0x00249249        // a₁ + 8b₁ + …
		d += (t >> 1) & 0x00249249 // a₁ + a₂ + 8(b₁ + b₂) + …
		d += (t >> 2) & 0x00249249 // a₁ + a₂ + a₃ + 4(b₁ + b₂ + b₃) + …

		for j := 0; j < 4; j++ {
			a := int16(d>>uint(6*j)) & 0x7   // a₁ + a₂ + a₃
			b := int16(d>>uint(6*j+3)) & 0x7 // b₁ + b₂ + b₃
			p[4*i+j] = a - b
		}
	}
}

// Sample p from a centered binomial distribution with n=4 and p=½ - that is:
// coefficients are in {-2, -1, 0, 1, 2} with probabilities {1/16, 1/4,
// 3/8, 1/4, 1/16}.
func (p *Poly) DeriveNoise2(seed []byte, nonce uint8) {
	keySuffix := [1]byte{nonce}
	h := shake.NewShake256()
	_, _ = h.Write(seed[:])
	_, _ = h.Write(keySuffix[:])

	// The distribution at hand is exactly the same as that
	// of (a + a') - (b + b') where a,a',b,b'~U(1).  Thus we need 4 bits per
	// coefficients, thus 128 bytes of input entropy.

	var buf [128]byte
	_, _ = h.Read(buf[:])

	// XXX 64 bits at a time?
	for i := 0; i < 32; i++ {
		// t is interpreted as a + 2a' + 4b + 8b' + ….
		t := binary.LittleEndian.Uint32(buf[4*i:])

		d := t & 0x55555555        // a + 4b + …
		d += (t >> 1) & 0x55555555 // a+a' + 4(b + b') + …

		for j := 0; j < 8; j++ {
			a := int16(d>>uint(4*j)) & 0x3   // a + a'
			b := int16(d>>uint(4*j+2)) & 0x3 // b + b'
			p[8*i+j] = a - b
		}
	}
}

// Sample p uniformly from the given seed and x and y coordinates.
//
// Coefficients are reduced.
func (p *Poly) DeriveUniform(seed *[32]byte, x, y uint8) {
	var seedSuffix [2]byte
	var buf [168]byte // rate of SHAKE-128

	seedSuffix[0] = x
	seedSuffix[1] = y

	h := shake.NewShake128()
	_, _ = h.Write(seed[:])
	_, _ = h.Write(seedSuffix[:])

	i := 0
	for {
		_, _ = h.Read(buf[:])

		for j := 0; j < 168; j += 3 {
			t1 := (uint16(buf[j]) | (uint16(buf[j+1]) << 8)) & 0xfff
			t2 := (uint16(buf[j+1]>>4) | (uint16(buf[j+2]) << 4)) & 0xfff

			if t1 < uint16(Q) {
				p[i] = int16(t1)
				i++

				if i == N {
					break
				}
			}

			if t2 < uint16(Q) {
				p[i] = int16(t2)
				i++

				if i == N {
					break
				}
			}
		}

		if i == N {
			break
		}
	}
}
