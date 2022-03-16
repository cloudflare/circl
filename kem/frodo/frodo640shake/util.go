package frodo640shake

func add(out *nbarByNbarU16, lhs *nbarByNbarU16, rhs *nbarByNbarU16) {
	for i := 0; i < len(out); i++ {
		out[i] = (lhs[i] + rhs[i]) & logQMask
	}
}

func sub(out *nbarByNbarU16, lhs *nbarByNbarU16, rhs *nbarByNbarU16) {
	for i := 0; i < len(out); i++ {
		out[i] = (lhs[i] - rhs[i]) & logQMask
	}
}

func pack(out []byte, in []uint16) {
	j := 0
	for i := 0; (i * 8) < len(in); i++ {
		in0 := in[i*8] & logQMask
		in1 := in[(i*8)+1] & logQMask
		in2 := in[(i*8)+2] & logQMask
		in3 := in[(i*8)+3] & logQMask
		in4 := in[(i*8)+4] & logQMask
		in5 := in[(i*8)+5] & logQMask
		in6 := in[(i*8)+6] & logQMask
		in7 := in[(i*8)+7] & logQMask

		out[j] |= byte(in0 >> 7)
		out[j+1] = (byte(in0&0x7F) << 1) | byte(in1>>14)

		out[j+2] = byte(in1 >> 6)
		out[j+3] = (byte(in1&0x3F) << 2) | byte(in2>>13)

		out[j+4] = byte(in2 >> 5)
		out[j+5] = (byte(in2&0x1F) << 3) | byte(in3>>12)

		out[j+6] = byte(in3 >> 4)
		out[j+7] = (byte(in3&0x0F) << 4) | byte(in4>>11)

		out[j+8] = byte(in4 >> 3)
		out[j+9] = (byte(in4&0x07) << 5) | byte(in5>>10)

		out[j+10] = byte(in5 >> 2)
		out[j+11] = (byte(in5&0x03) << 6) | byte(in6>>9)

		out[j+12] = byte(in6 >> 1)
		out[j+13] = (byte(in6&0x01) << 7) | byte(in7>>8)

		out[j+14] = byte(in7)
		j += 15
	}
}

func unpack(out []uint16, in []byte) {
	j := 0
	for i := 0; (i * 15) < len(in); i++ {
		in0 := in[i*15]
		in1 := in[(i*15)+1]
		in2 := in[(i*15)+2]
		in3 := in[(i*15)+3]
		in4 := in[(i*15)+4]
		in5 := in[(i*15)+5]
		in6 := in[(i*15)+6]
		in7 := in[(i*15)+7]
		in8 := in[(i*15)+8]
		in9 := in[(i*15)+9]
		in10 := in[(i*15)+10]
		in11 := in[(i*15)+11]
		in12 := in[(i*15)+12]
		in13 := in[(i*15)+13]
		in14 := in[(i*15)+14]

		out[j] = (uint16(in0) << 7) | (uint16(in1&0xFE) >> 1)
		out[j+1] = (uint16(in1&0x1) << 14) | (uint16(in2) << 6) | (uint16(in3&0xFC) >> 2)

		out[j+2] = (uint16(in3&0x03) << 13) | (uint16(in4) << 5) | (uint16(in5&0xF8) >> 3)
		out[j+3] = (uint16(in5&0x07) << 12) | (uint16(in6) << 4) | (uint16(in7&0xF0) >> 4)

		out[j+4] = (uint16(in7&0x0F) << 11) | (uint16(in8) << 3) | (uint16(in9&0xE0) >> 5)
		out[j+5] = (uint16(in9&0x1F) << 10) | (uint16(in10) << 2) | (uint16(in11&0xC0) >> 6)

		out[j+6] = (uint16(in11&0x3F) << 9) | (uint16(in12) << 1) | (uint16(in13&0x80) >> 7)
		out[j+7] = (uint16(in13&0x7F) << 8) | uint16(in14)
		j += 8
	}
}

func encodeMessage(out *nbarByNbarU16, msg *[messageSize]byte) {
	extractedBitsMask := uint16((1 << extractedBits) - 1)
	outPos := 0

	for i := 0; (i * 2) < len(msg); i++ {
		in := uint16(msg[i*2]) | (uint16(msg[(i*2)+1]) << 8)
		for j := 0; j < (16 / extractedBits); j++ { // 16 = bit size of out[i]
			out[outPos] = (in & extractedBitsMask) << (logQ - extractedBits)
			outPos++

			in >>= extractedBits
		}
	}
}

func decodeMessage(out *[messageSize]byte, msg *nbarByNbarU16) {
	extractedBitsMask := uint16((1 << extractedBits) - 1)
	msgPos := 0

	for i := 0; i < len(out); i++ {
		for j := 0; j < (8 / extractedBits); j++ {
			temp := (msg[msgPos] & logQMask) + (1 << (logQ - extractedBits - 1))
			temp >>= (logQ - extractedBits)
			temp &= extractedBitsMask
			out[i] |= byte(temp) << (j * extractedBits)
			msgPos++
		}
	}
}

func mulAddSBPlusE(out *nbarByNbarU16, s []uint16, b *nByNbarU16, e []uint16) {
	// Multiply by s on the left
	// Inputs: b (N x N_BAR), s (N_BAR x N), e (N_BAR x N_BAR)
	// Output: out = s*b + e (N_BAR x N_BAR)

	for k := 0; k < paramNbar; k++ {
		for i := 0; i < paramNbar; i++ {
			out[k*paramNbar+i] = e[k*paramNbar+i]
			for j := 0; j < paramN; j++ {
				out[k*paramNbar+i] += s[k*paramN+j] * b[j*paramNbar+i]
			}
			out[k*paramNbar+i] = out[k*paramNbar+i] & logQMask
		}
	}
}

func mulBS(out *nbarByNbarU16, b *nbarByNU16, s *nByNbarU16) {
	for i := 0; i < paramNbar; i++ {
		for j := 0; j < paramNbar; j++ {
			out[i*paramNbar+j] = 0
			for k := 0; k < paramN; k++ {
				out[i*paramNbar+j] += b[i*paramN+k] * s[j*paramN+k]
			}
			out[i*paramNbar+j] = out[i*paramNbar+j] & logQMask
		}
	}
}

func ctCompareU16(lhs []uint16, rhs []uint16) int {
	// Compare lhs and rhs in constant time.
	// Returns 0 if they are equal, 1 otherwise.
	if len(lhs) != len(rhs) {
		return 1
	}

	var v uint16

	for i := range lhs {
		v |= lhs[i] ^ rhs[i]
	}

	return int((v | -v) >> 15)
}
