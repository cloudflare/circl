package frodo640shake

func min(x uint, y uint) uint {
	if x < y {
		return x
	}
	return y
}

func add(out *[paramNbar * paramNbar]uint16, lhs *[paramNbar * paramNbar]uint16, rhs *[paramNbar * paramNbar]uint16) {
	for i := 0; i < len(out); i++ {
		out[i] = (lhs[i] + rhs[i]) & logQMask
	}
}

func sub(out *[paramNbar * paramNbar]uint16, lhs *[paramNbar * paramNbar]uint16, rhs *[paramNbar * paramNbar]uint16) {
	for i := 0; i < len(out); i++ {
		out[i] = (lhs[i] - rhs[i]) & logQMask
	}
}

func pack(out []byte, in []uint16) {
	outBitsFree := uint(0)
	inBitsLeft := uint(0)
	var inElem uint16

	j := -1
	for i := 0; i < len(in); {
		if outBitsFree == 0 {
			outBitsFree = 8
			j += 1
			out[j] = 0
		}

		if inBitsLeft == 0 {
			inElem = in[i]
			inBitsLeft = logQ
			i += 1
		}

		toCopy := min(outBitsFree, inBitsLeft)
		outBitsFree -= toCopy
		inBitsLeft -= toCopy

		var mask uint16 = (1 << toCopy) - 1

		out[j] |= byte((inElem>>inBitsLeft)&mask) << outBitsFree
	}

	out[j+1] = byte(inElem)
}

func unpack(out []uint16, in []byte) {
	var outBitsFree uint = 0
	var inBitsLeft uint = 0
	var inByte byte

	j := -1
	for i := 0; i < len(in); {
		if outBitsFree == 0 {
			outBitsFree = logQ
			j += 1
			out[j] = 0
		}

		if inBitsLeft == 0 {
			inByte = in[i]
			inBitsLeft = 8
			i += 1
		}

		toCopy := min(outBitsFree, inBitsLeft)
		outBitsFree -= toCopy
		inBitsLeft -= toCopy

		mask := byte((1 << toCopy) - 1)

		out[j] |= uint16((inByte>>inBitsLeft)&mask) << outBitsFree
	}
}

func encodeMessage(out *[paramNbar * paramNbar]uint16, msg *[messageSize]byte) {
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

func decodeMessage(out *[messageSize]byte, msg *[paramNbar * paramNbar]uint16) {
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

func mulAddSBPlusE(out *[paramNbar * paramNbar]uint16, s []uint16, b *[paramN * paramNbar]uint16, e []uint16) {
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

func mulBS(out *[paramNbar * paramNbar]uint16, b *[paramNbar * paramN]uint16, s *[paramN * paramNbar]uint16) {
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
