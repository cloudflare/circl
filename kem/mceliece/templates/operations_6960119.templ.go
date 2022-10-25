// +build ignore
// The previous line (and this one up to the warning below) is removed by the
// template generator.

// Code generated from operations_6960119.templ.go. DO NOT EDIT.

package {{.Pkg}}

// This function determines (in a constant-time manner) whether the padding bits of `pk` are all zero.
func checkPkPadding(pk *[PublicKeySize]byte) byte {
	b := byte(0)
	for i := 0; i < pkNRows; i++ {
		b |= pk[i*pkRowBytes+pkRowBytes-1]
	}
	b >>= pkNCols % 8
	b -= 1
	b >>= 7
	return b - 1
}

// This function determines (in a constant-time manner) whether the padding bits of `c` are all zero.
func checkCPadding(c *[CiphertextSize]byte) byte {
	b := c[syndBytes-1] >> (pkNRows % 8)
	b -= 1
	b >>= 7
	return b - 1
}

// input: public key pk, error vector e
// output: syndrome s
func syndrome(s *[CiphertextSize]byte, pk *[PublicKeySize]byte, e *[sysN / 8]byte) {
	row := [sysN / 8]byte{}
	tail := pkNRows % 8
	for i := 0; i < syndBytes; i++ {
		s[i] = 0
	}
	for i := 0; i < pkNRows; i++ {
		for j := 0; j < sysN/8; j++ {
			row[j] = 0
		}
		for j := 0; j < pkRowBytes; j++ {
			row[sysN/8-pkRowBytes+j] = pk[i*pkRowBytes+j]
		}
		for j := sysN/8 - 1; j >= sysN/8-pkRowBytes; j-- {
			row[j] = (row[j] << tail) | (row[j-1] >> (8 - tail))
		}
		row[i/8] |= 1 << (i % 8)

		b := byte(0)
		for j := 0; j < sysN/8; j++ {
			b ^= row[j] & e[j]
		}

		b ^= b >> 4
		b ^= b >> 2
		b ^= b >> 1
		b &= 1

		s[i/8] |= b << (i % 8)
	}
}