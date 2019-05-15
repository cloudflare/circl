// Package math provides some utility functions for converting big integer numbers.
package math

import (
	"fmt"
	"math/big"
	"strings"
)

// Absolute returns always a positive value.
func Absolute(x int32) int32 {
	mask := x >> 31
	return (x + mask) ^ mask
}

// BytesLe2Hex returns an hexadecimal string of a number stored in a
// little-endian order slice x.
func BytesLe2Hex(x []byte) string {
	b := &strings.Builder{}
	b.Grow(2*len(x) + 2)
	fmt.Fprint(b, "0x")
	if len(x) == 0 {
		fmt.Fprint(b, "00")
	}
	for i := len(x) - 1; i >= 0; i-- {
		fmt.Fprintf(b, "%02x", x[i])
	}
	return b.String()
}

// BytesLe2BigInt converts a little-endian slice x into a big-endian
// math/big.Int.
func BytesLe2BigInt(x []byte) *big.Int {
	n := len(x)
	b := new(big.Int)
	if len(x) > 0 {
		y := make([]byte, n)
		for i := 0; i < n; i++ {
			y[n-1-i] = x[i]
		}
		b.SetBytes(y)
	}
	return b
}

// BigInt2BytesLe stores a positive big.Int number x into a little-endian slice z.
// The slice is modified if the bitlength of x <= 8*len(z) (padding with zeros).
// If x does not fit in the slice or is negative, z is not modified.
func BigInt2BytesLe(z []byte, x *big.Int) {
	xLen := (x.BitLen() + 7) >> 3
	zLen := len(z)
	if zLen >= xLen && x.Sign() >= 0 {
		y := x.Bytes()
		for i := 0; i < xLen; i++ {
			z[i] = y[xLen-1-i]
		}
		for i := xLen; i < zLen; i++ {
			z[i] = 0
		}
	}
}
