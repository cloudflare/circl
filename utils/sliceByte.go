package utils

import (
	nonCryptoRand "crypto/rand"
	"fmt"
	"math/big"
	cryptoRand "math/rand"
)

// NonCryptoRand fills x with random numbers. This function is not cryptographic
// secure and cannot be used to generate keys.
func NonCryptoRand(x []byte) { _, _ = nonCryptoRand.Read(x) }

// CryptoRand fills x with random numbers. This function provides a uniform
// distribution of the output values.
func CryptoRand(x []byte) { _, _ = cryptoRand.Read(x) }

// Num2Hex returns a hexadecimal string of a number stored at x in little-endian
// order.
func Num2Hex(x []byte) string {
	s := "0x"
	for i := len(x) - 1; i >= 0; i-- {
		s += fmt.Sprintf("%02x", x[i])
	}
	return s
}

// Num2BigInt converts a little-endian slice into a big-endian math/big.Int.
func Num2BigInt(x []byte) *big.Int {
	n := len(x)
	y := make([]byte, n)
	for i := 0; i < n; i++ {
		y[n-1-i] = x[i]
	}
	return new(big.Int).SetBytes(y)
}

// BigInt2Num converts a big-endian math/big.Int into a little-endian slice of size n.
func BigInt2Num(x *big.Int, n uint) []byte {
	z := make([]byte, n)
	y := x.Bytes()
	m := len(y)
	if m <= int(n) {
		for i := 0; i < m; i++ {
			z[i] = y[m-1-i]
		}
	} else {
		panic("x is too big")
	}
	return z
}
