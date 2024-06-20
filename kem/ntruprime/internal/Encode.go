package internal

/* 0 <= R[i] < M[i] < 16384 */
func Encode(out []uint8, R []uint16, M []uint16, len int) {
	if len > 1 {
		R2 := make([]uint16, (len+1)/2)
		M2 := make([]uint16, (len+1)/2)
		var i int
		for ; len > 1; len = (len + 1) / 2 {
			for i = 0; i < len-1; i += 2 {
				m0 := uint32(M[i])
				r := uint32(R[i]) + uint32(R[i+1])*m0
				m := uint32(M[i+1]) * m0
				for m >= 16384 {
					out[0] = uint8(r)
					out = out[1:]

					r >>= 8
					m = (m + 255) >> 8
				}
				R2[i/2] = uint16(r)
				M2[i/2] = uint16(m)
			}
			if i < len {
				R2[i/2] = R[i]
				M2[i/2] = M[i]
			}
			copy(R, R2)
			copy(M, M2)
		}
	}
	if len == 1 {
		r := R[0]
		m := M[0]
		for m > 1 {
			out[0] = uint8(r)
			out = out[1:]
			r >>= 8
			m = (m + 255) >> 8
		}
	}
}
