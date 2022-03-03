package common

import "encoding/binary"

// Constant time select.
// if pick == 1 (out = in1)
// if pick == 0 (out = in2)
// else out is undefined.
func Cpick(pick int, out, in1, in2 []byte) {
	which := byte((int8(pick << 7)) >> 7)
	for i := range out {
		out[i] = (in1[i] & which) | (in2[i] & ^which)
	}
}

// Read 2*bytelen(p) bytes into the given ExtensionFieldElement.
//
// It is an error to call this function if the input byte slice is less than 2*bytelen(p) bytes long.
func BytesToFp2(fp2 *Fp2, input []byte, bytelen int) {
	if len(input) < 2*bytelen {
		panic("input byte slice too short")
	}
	numW64 := (bytelen*8 + 63) / 64
	a := make([]byte, 8*numW64)
	b := make([]byte, 8*numW64)
	copy(a[:bytelen], input[:bytelen])
	copy(b[:bytelen], input[bytelen:])
	for i := 0; i < numW64; i++ {
		fp2.A[i] = binary.LittleEndian.Uint64(a[i*8 : (i+1)*8])
		fp2.B[i] = binary.LittleEndian.Uint64(b[i*8 : (i+1)*8])
	}
}

// Convert the input to wire format.
//
// The output byte slice must be at least 2*bytelen(p) bytes long.
func Fp2ToBytes(output []byte, fp2 *Fp2, bytelen int) {
	if len(output) < 2*bytelen {
		panic("output byte slice too short")
	}
	numW64 := (bytelen*8 + 63) / 64
	a := make([]byte, 8*numW64)
	b := make([]byte, 8*numW64)
	for i := 0; i < numW64; i++ {
		binary.LittleEndian.PutUint64(a[i*8:(i+1)*8], fp2.A[i])
		binary.LittleEndian.PutUint64(b[i*8:(i+1)*8], fp2.B[i])
	}
	copy(output[:bytelen], a[:bytelen])
	copy(output[bytelen:], b[:bytelen])
}
