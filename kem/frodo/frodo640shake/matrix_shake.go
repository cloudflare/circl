package frodo640shake

import (
	"github.com/cloudflare/circl/internal/sha3"
)

func expandSeedIntoA(A []uint16, seed []byte, xof sha3.State) error {
	var ARow [paramN * 2]byte
	var seedSeparated [2 + seedASize]byte

	copy(seedSeparated[2:], seed)

	for i := 0; i < paramN; i++ {
		seedSeparated[0] = byte(i)
		seedSeparated[1] = byte(i >> 8)

		xof.Reset()
		_, err := xof.Write(seedSeparated[:])
		if err != nil {
			return err
		}
		_, err = xof.Read(ARow[:])
		if err != nil {
			return err
		}

		for j := 0; j < paramN; j++ {
			A[(i*paramN)+j] = uint16(ARow[j*2]) | (uint16(ARow[(j*2)+1]) << 8)
		}
	}
	return nil
}

func mulAddASPlusE(out []uint16, s []uint16, e []uint16, A []uint16) {
	copy(out, e)

	for i := 0; i < paramN; i++ {
		for k := 0; k < paramNbar; k++ {
			var sum uint16 = 0
			for j := 0; j < paramN; j++ {
				sum += A[i*paramN+j] * s[k*paramN+j]
			}
			// Adding e. No need to reduce modulo 2^15, extra bits are taken
			// care of during packing later on.
			out[i*paramNbar+k] += sum
		}
	}
}

func mulAddSAPlusE(out []uint16, s []uint16, e []uint16, A []uint16) {
	copy(out, e)

	for i := 0; i < paramN; i++ {
		for k := 0; k < paramNbar; k++ {
			var sum uint16 = 0
			for j := 0; j < paramN; j++ {
				sum += A[j*paramN+i] * s[k*paramN+j]
			}
			// Adding e. No need to reduce modulo 2^15, extra bits are taken
			// care of during packing later on.
			out[k*paramN+i] += sum
		}
	}
}
