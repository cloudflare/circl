package math

import "math/bits"

func NextPow2(n uint) (twoN uint, N uint) {
	if bits.OnesCount(n) == 1 {
		return n, uint(bits.TrailingZeros(n))
	} else {
		N = uint(bits.Len(n))
		return uint(1) << N, N
	}
}
