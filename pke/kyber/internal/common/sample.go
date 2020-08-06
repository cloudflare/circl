package common

import (
	"github.com/cloudflare/circl/internal/shake"

	"encoding/binary"
)

// Sample p from a centered binomial distribution with n=4 and p=½ - that is:
// coefficients are in {-2, -1, 0, 1, 2} with probabilities {1/16, 1/4,
// 3/8, 1/4, 1/16}.
func (p *Poly) DeriveNoise(seed []byte, nonce uint8) {
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
		// Byte is interpreted as a + 2a' + 4b + 8b' + \ldots.
		t := binary.LittleEndian.Uint32(buf[4*i:])

		d := t & 0x55555555        // a + 4b + \ldots
		d += (t >> 1) & 0x55555555 // a+a' + 4(b + b') + \ldots

		for j := 0; j < 8; j++ {
			a := int16(d>>uint(4*j)) & 0x3   // a + a'
			b := int16(d>>uint(4*j+2)) & 0x3 // b + b'
			p[8*i+j] = a - b
		}
	}
}

// Sample p uniformly from the given seed and x and y coordinates.
//
// Coefficients are not reduced, but 0 ≤ p[i] ≤ 4.5q.
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

		for j := 0; j < 168 && i < N; j += 2 {
			t := uint16(buf[j]) | (uint16(buf[j+1]) << 8)

			// 19q is the largest multiple of q below 2¹⁶.
			if t < 19*uint16(Q) {
				// This is sloppy Barrett reduction: 1/2¹² is an approximation
				// of 1/q, but not good enough to fully reduce modulo q.
				// (See barrettReduce() for proper Barrett reduction.)
				// This ensures that t ≤ 4.5q.
				t -= (t >> 12) * uint16(Q)
				p[i] = int16(t)
				i++
			}
		}

		if i == N {
			break
		}
	}
}
