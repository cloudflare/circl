package conv

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"math/bits"
	"strings"
)

// Hex2BytesLe returns a little-endian byte slice representing an hexadecimal
// number. The input must not have the '0x' preffix.
func Hex2BytesLe(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// BytesLe2Hex returns an hexadecimal string of a number stored in a
// little-endian order slice x.
func BytesLe2Hex(x []byte) string {
	b := new(strings.Builder)
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

// Uint64Le2Hex returns an hexadecimal string of a number stored in a
// little-endian order slice x.
func Uint64Le2Hex(x []uint64) string {
	b := new(strings.Builder)
	b.Grow(16*len(x) + 2)
	fmt.Fprint(b, "0x")
	if len(x) == 0 {
		fmt.Fprint(b, "00")
	}
	for i := len(x) - 1; i >= 0; i-- {
		fmt.Fprintf(b, "%016x", x[i])
	}
	return b.String()
}

// UintLe2Hex returns an hexadecimal string of a number stored in a
// little-endian order slice x.
func UintLe2Hex(x []uint) string {
	b := new(strings.Builder)
	b.Grow((bits.UintSize/4)*len(x) + 2)
	fmt.Fprint(b, "0x")
	if len(x) == 0 {
		fmt.Fprint(b, "00")
	}
	for i := len(x) - 1; i >= 0; i-- {
		fmt.Fprintf(b, fmt.Sprintf("%%0%vx", bits.UintSize/4), x[i])
	}
	return b.String()
}

// Uint64Le2BigInt converts a llitle-endian slice x into a big number.
func Uint64Le2BigInt(x []uint64) *big.Int {
	n := len(x)
	b := new(big.Int)
	var bi big.Int
	for i := n - 1; i >= 0; i-- {
		bi.SetUint64(x[i])
		b.Lsh(b, 64)
		b.Add(b, &bi)
	}
	return b
}

// BigInt2Uint64Le stores a positive big.Int number x into a little-endian slice z.
// The slice is modified if the bitlength of x <= 8*len(z) (padding with zeros).
// If x does not fit in the slice or is negative, z is not modified.
func BigInt2Uint64Le(z []uint64, x *big.Int) {
	xLen := (x.BitLen() + 63) >> 6 // number of 64-bit words
	zLen := len(z)
	if zLen >= xLen && x.Sign() > 0 {
		var y, yi big.Int
		y.Set(x)
		two64 := big.NewInt(1)
		two64.Lsh(two64, 64).Sub(two64, big.NewInt(1))
		for i := 0; i < xLen; i++ {
			yi.And(&y, two64)
			z[i] = yi.Uint64()
			y.Rsh(&y, 64)
		}
	}
	for i := xLen; i < zLen; i++ {
		z[i] = 0
	}
}
