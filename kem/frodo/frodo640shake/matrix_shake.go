package frodo640shake

import (
	"github.com/cloudflare/circl/internal/sha3"
)

func expandSeedIntoA(A *nByNU16, seed *[seedASize]byte, xof *sha3.State) {
	var ARow [paramN * 2]byte
	var seedSeparated [2 + seedASize]byte

	copy(seedSeparated[2:], seed[:])

	for i := 0; i < paramN; i++ {
		seedSeparated[0] = byte(i)
		seedSeparated[1] = byte(i >> 8)

		xof.Reset()
		_, _ = xof.Write(seedSeparated[:])
		_, _ = xof.Read(ARow[:])

		for j := 0; j < paramN; j++ {
			// No need to reduce modulo 2^15, extra bits are removed
			// later on via packing or explicit reduction.
			A[(i*paramN)+j] = uint16(ARow[j*2]) | (uint16(ARow[(j*2)+1]) << 8)
		}
	}
}

func mulAddASPlusE(out *nByNbarU16, A *nByNU16, s *nByNbarU16, e *nByNbarU16) {
	for i := 0; i < paramN; i++ {
		for k := 0; k < paramNbar; k++ {
			sum := e[i*paramNbar+k]
			for j := 0; j < paramN; j++ {
				sum += A[i*paramN+j] * s[k*paramN+j]
			}
			// No need to reduce modulo 2^15, extra bits are removed
			// later on via packing or explicit reduction.
			out[i*paramNbar+k] += sum
		}
	}
}

func mulAddSAPlusE(out *nbarByNU16, s []uint16, A *nByNU16, e []uint16) {
	for i := 0; i < paramN; i++ {
		for k := 0; k < paramNbar; k++ {
			sum := e[k*paramN+i]
			for j := 0; j < paramN; j++ {
				sum += A[j*paramN+i] * s[k*paramN+j]
			}
			// No need to reduce modulo 2^15, extra bits are removed
			// later on via packing or explicit reduction.
			out[k*paramN+i] += sum
		}
	}
}
