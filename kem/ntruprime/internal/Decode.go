package internal

/* Decode(R,s,M,len) */
/* assumes 0 < M[i] < 16384 */
/* produces 0 <= R[i] < M[i] */
func Decode(out []uint16, S []uint8, M []uint16, len int) {
	index := 0
	if len == 1 {
		if M[0] == 1 {
			out[index] = 0
		} else if M[0] <= 256 {
			out[index] = Uint32_mod_uint14(uint32(S[0]), M[0])
		} else {
			out[index] = Uint32_mod_uint14(uint32(uint16(S[0])+((uint16(S[1]))<<8)), M[0])
		}
	}
	if len > 1 {
		R2 := make([]uint16, (len+1)/2)
		M2 := make([]uint16, (len+1)/2)
		bottomr := make([]uint16, len/2)
		bottomt := make([]uint32, len/2)
		i := 0
		for i = 0; i < len-1; i += 2 {
			m := uint32(M[i]) * uint32(M[i+1])

			if m > 256*16383 {
				bottomt[i/2] = 256 * 256
				bottomr[i/2] = uint16(S[0]) + 256*uint16(S[1])
				S = S[2:]
				M2[i/2] = uint16((((m + 255) >> 8) + 255) >> 8)
			} else if m >= 16384 {
				bottomt[i/2] = 256
				bottomr[i/2] = uint16(S[0])
				S = S[1:]
				M2[i/2] = uint16((m + 255) >> 8)

			} else {
				bottomt[i/2] = 1
				bottomr[i/2] = 0
				M2[i/2] = uint16(m)
			}
		}
		if i < len {
			M2[i/2] = M[i]
		}

		Decode(R2, S, M2, (len+1)/2)

		for i = 0; i < len-1; i += 2 {
			var r uint32 = uint32(bottomr[i/2])
			var r1 uint32
			var r0 uint16

			r += bottomt[i/2] * uint32(R2[i/2])
			Uint32_divmod_uint14(&r1, &r0, r, M[i])
			r1 = uint32(Uint32_mod_uint14(r1, M[i+1])) /* only needed for invalid inputs */

			out[index] = r0
			index++
			out[index] = uint16(r1)
			index++

		}
		if i < len {
			out[index] = R2[i/2]
			index++
		}

	}
}
