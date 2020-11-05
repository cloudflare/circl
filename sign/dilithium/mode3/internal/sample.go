package internal

import (
	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/simd/keccakf1600"

	"github.com/cloudflare/circl/sign/dilithium/internal/common"

	"encoding/binary"
)

// DeriveX4Available indicates whether the system supports the quick fourway
// sampling variants like PolyDeriveUniformX4.
var DeriveX4Available = keccakf1600.IsEnabledX4() && !UseAES

// For each i, sample ps[i] uniformly with coefficients of norm less than γ₁
// using the the given seed and nonces[i].  ps[i] may be nil and is ignored
// in that case.  ps[i] will not be normalized, but have coefficients in the
// interval (q-γ₁,q+γ₁).
//
// Can only be called when DeriveX4Available is true.
func PolyDeriveUniformLeGamma1X4(ps [4]*common.Poly, seed *[48]byte,
	nonces [4]uint16) {
	var perm keccakf1600.StateX4
	state := perm.Initialize()

	// Absorb the seed in the four states
	for i := 0; i < 6; i++ {
		v := binary.LittleEndian.Uint64(seed[8*i : 8*(i+1)])
		for j := 0; j < 4; j++ {
			state[i*4+j] = v
		}
	}

	// Absorb the nonces, the SHAKE256 domain separator (0b1111), the
	// start of the padding (0b...001) and the end of the padding 0b100...
	// Recall that the rate of SHAKE256 is 136 --- i.e. 17 uint64s.
	for j := 0; j < 4; j++ {
		state[6*4+j] = uint64(nonces[j]) | (0x1f << 16)
		state[16*4+j] = 0x80 << 56
	}

	var idx [4]int // indices into ps
	for j := 0; j < 4; j++ {
		if ps[j] == nil {
			idx[j] = common.N // mark nil polynomial as completed
		}
	}

	// Each try requires 15 bits.  15 does not divide into 64, nor in 136,
	// so we will have to carry some bits from a previous uint64 to the next.
	var carry [4]uint32

	// Shift is the amount of bits in the carry.
	var shift [4]uint

	done := false
	for !done {
		// Applies KeccaK-f[1600] to state to get the next 17 uint64s of each
		// of the four SHAKE256 streams.
		perm.Permute()

		done = true

	PolyLoop:
		for j := 0; j < 4; j++ {
			if idx[j] == common.N {
				continue
			}

			for i := 0; i < 17; i++ {
				var t [4]uint32
				tCount := 3

				// Get the next three or four 20 bit numbers.
				qw := state[i*4+j]
				qwl := (qw << shift[j]) | uint64(carry[j])
				t[0] = uint32(qwl & 0xfffff)
				t[1] = uint32((qwl >> 20) & 0xfffff)
				t[2] = uint32((qwl >> 40) & 0xfffff)

				if shift[j] == 16 {
					t[3] = uint32(qw >> 44)
					shift[j] = 0
					carry[j] = 0
					tCount = 4
				} else {
					shift[j] += 4
					carry[j] = uint32(qw >> (64 - shift[j]))
				}

				// Check if they're coefficients.
				for k := 0; k < tCount; k++ {
					if t[k] <= 2*common.Gamma1-2 {
						ps[j][idx[j]] = common.Q + common.Gamma1 - 1 - t[k]
						idx[j]++
						if idx[j] == common.N {
							continue PolyLoop
						}
					}
				}
			}

			done = false
		}
	}
}

// For each i, sample ps[i] uniformly from the given seed and nonces[i].
// ps[i] may be nil and is ignored in that case.
//
// Can only be called when DeriveX4Available is true.
func PolyDeriveUniformX4(ps [4]*common.Poly, seed *[32]byte, nonces [4]uint16) {
	var perm keccakf1600.StateX4
	state := perm.Initialize()

	// Absorb the seed in the four states
	for i := 0; i < 4; i++ {
		v := binary.LittleEndian.Uint64(seed[8*i : 8*(i+1)])
		for j := 0; j < 4; j++ {
			state[i*4+j] = v
		}
	}

	// Absorb the nonces, the SHAKE128 domain separator (0b1111), the
	// start of the padding (0b...001) and the end of the padding 0b100...
	// Recall that the rate of SHAKE128 is 168 --- i.e. 21 uint64s.
	for j := 0; j < 4; j++ {
		state[4*4+j] = uint64(nonces[j]) | (0x1f << 16)
		state[20*4+j] = 0x80 << 56
	}

	var idx [4]int // indices into ps
	for j := 0; j < 4; j++ {
		if ps[j] == nil {
			idx[j] = common.N // mark nil polynomial as completed
		}
	}

	done := false
	for !done {
		// Applies KeccaK-f[1600] to state to get the next 21 uint64s of each
		// of the four SHAKE128 streams.
		perm.Permute()

		done = true

	PolyLoop:
		for j := 0; j < 4; j++ {
			if idx[j] == common.N {
				continue
			}
			for i := 0; i < 7; i++ {
				var t [8]uint32
				t[0] = uint32(state[i*3*4+j] & 0x7fffff)
				t[1] = uint32((state[i*3*4+j] >> 24) & 0x7fffff)
				t[2] = uint32((state[i*3*4+j] >> 48) |
					((state[(i*3+1)*4+j] & 0x7f) << 16))
				t[3] = uint32((state[(i*3+1)*4+j] >> 8) & 0x7fffff)
				t[4] = uint32((state[(i*3+1)*4+j] >> 32) & 0x7fffff)
				t[5] = uint32((state[(i*3+1)*4+j] >> 56) |
					((state[(i*3+2)*4+j] & 0x7fff) << 8))
				t[6] = uint32((state[(i*3+2)*4+j] >> 16) & 0x7fffff)
				t[7] = uint32((state[(i*3+2)*4+j] >> 40) & 0x7fffff)

				for k := 0; k < 8; k++ {
					if t[k] < common.Q {
						ps[j][idx[j]] = t[k]
						idx[j]++
						if idx[j] == common.N {
							continue PolyLoop
						}
					}
				}
			}
			done = false
		}
	}
}

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
		h := sha3.NewShake128()
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

		h := sha3.NewShake128()
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
	if !DeriveX4Available {
		for i := 0; i < L; i++ {
			PolyDeriveUniformLeGamma1(&v[i], seed, nonce+uint16(i))
		}
		return
	}

	var ps [4]*common.Poly
	nonces := [4]uint16{nonce, nonce + 1, nonce + 2, nonce + 3}
	for i := 0; i < L && i < 4; i++ {
		ps[i] = &v[i]
	}

	// PolyDeriveUniformLeGamma1X4 is slower than, but not twice as slow as,
	// PolyDeriveUniformLeGamma.
	PolyDeriveUniformLeGamma1X4(ps, seed, nonces)
	if L == 5 {
		PolyDeriveUniformLeGamma1(&v[L-1], seed, nonce+4)
	} else if L > 5 || L < 2 {
		panic("VecLDeriveUniformLeGamma1 does not support that L")
	}
}

// Sample p uniformly with coefficients of norm less than γ₁ using the
// given seed and nonce.
//
// p will not be normalized, but have coefficients in the
// interval (q-γ₁,q+γ₁).
func PolyDeriveUniformLeGamma1(p *common.Poly, seed *[48]byte, nonce uint16) {
	// Assumes γ₁ is less than 2²⁰.
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

		h := sha3.NewShake256()
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

// For each i, sample ps[i] uniformly with 60 non-zero coefficients in {q-1,1}
// using the the given seed and w1[i].  ps[i] may be nil and is ignored
// in that case.  ps[i] will be normalized.
//
// Can only be called when DeriveX4Available is true.
//
// This function is currently not used (yet).
func PolyDeriveUniformB60X4(ps [4]*common.Poly, seed *[48]byte,
	w1 [4]*VecK) {
	// Pack the w1s
	var w1Packed [4][common.PolyLe16Size * K]byte
	for j := 0; j < 4; j++ {
		if ps[j] != nil {
			w1[j].PackLe16(w1Packed[j][:])
		}
	}

	var perm keccakf1600.StateX4
	state := perm.Initialize()

	// Absorb the seed in the four states
	for i := 0; i < 6; i++ {
		v := binary.LittleEndian.Uint64(seed[8*i : 8*(i+1)])
		for j := 0; j < 4; j++ {
			state[i*4+j] = v
		}
	}

	// Absorb the start of the packed w₁s
	offset := 0 // offset into w1Packed[j]
	for i := 6; i < 17; i++ {
		for j := 0; j < 4; j++ {
			state[i*4+j] = binary.LittleEndian.Uint64(w1Packed[j][offset : offset+8])
		}
		offset += 8
	}

	offset -= 8

	// Absorb the remainder of the packed w₁s.
PermuteLoop:
	for {
		perm.Permute()

		for i := 0; i < 17; i++ {
			offset += 8
			if offset == len(w1Packed[0]) {
				// SHAKE256 domain separator and padding
				for j := 0; j < 4; j++ {
					state[i*4+j] ^= 0x1f
					state[16*4+j] ^= 0x80 << 56
				}
				perm.Permute()

				break PermuteLoop
			}

			for j := 0; j < 4; j++ {
				state[i*4+j] ^= binary.LittleEndian.Uint64(
					w1Packed[j][offset : offset+8])
			}
		}
	}

	var signs [4]uint64
	var idx [4]uint16 // indices into ps

	for j := 0; j < 4; j++ {
		if ps[j] != nil {
			signs[j] = state[j]
			*ps[j] = common.Poly{} // zero ps[j]
			idx[j] = common.N - 60
		} else {
			idx[j] = common.N // mark as completed
		}
	}

	stateOffset := 1
	for {
		done := true

	PolyLoop:
		for j := 0; j < 4; j++ {
			if idx[j] == common.N {
				continue
			}

			for i := stateOffset; i < 17; i++ {
				var bs [8]byte
				binary.LittleEndian.PutUint64(bs[:], state[4*i+j])
				for k := 0; k < 8; k++ {
					b := uint16(bs[k])

					if b > idx[j] {
						continue
					}

					ps[j][idx[j]] = ps[j][b]
					ps[j][b] = 1
					// Takes least significant bit of signs and uses it for the sign.
					// Note 1 ^ (1 | (Q-1)) = Q-1.
					ps[j][b] ^= uint32((-(signs[j] & 1)) & (1 | (common.Q - 1)))
					signs[j] >>= 1

					idx[j]++
					if idx[j] == common.N {
						continue PolyLoop
					}
				}
			}

			done = false
		}

		if done {
			break
		}

		perm.Permute()
		stateOffset = 0
	}
}

// Samples p uniformly with 60 non-zero coefficients in {q-1,1}.
//
// The polynomial p will be normalized.
func PolyDeriveUniformB60(p *common.Poly, seed *[48]byte, w1 *VecK) {
	var w1Packed [common.PolyLe16Size * K]byte
	var buf [136]byte // SHAKE-256 rate is 136

	w1.PackLe16(w1Packed[:])

	h := sha3.NewShake256()
	_, _ = h.Write(seed[:])
	_, _ = h.Write(w1Packed[:])
	_, _ = h.Read(buf[:])

	// Essentially we generate a sequence of 60 ones or minus ones,
	// prepend 196 zeroes and shuffle the concatenation using the
	// usual algorithm (Fisher--Yates.)
	signs := binary.LittleEndian.Uint64(buf[:])
	bufOff := 8 // offset into buf

	*p = common.Poly{} // zero p
	for i := uint16(common.N - 60); i < common.N; i++ {
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
