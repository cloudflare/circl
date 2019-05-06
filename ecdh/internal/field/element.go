// Package field provides arithmetic field operations over GF(2^255-19) and
// GF(2^448-2^224-1). Elements are represented as an array of bytes which can
// be operated using methods of the Arith255 and Arith448 interfaces.
package field

//go:generate go run templates/gen.go

import (
	"fmt"
	"math/big"
)

// SizeFp255 size in bytes of an Element255
const SizeFp255 = 32

// SizeFp448 size in bytes of an Element448
const SizeFp448 = 56

// Element255 represents a prime field element in little-endian order.
type Element255 [SizeFp255]byte

// Element448 represents a prime field element in little-endian order.
type Element448 [SizeFp448]byte

// bigElement255 represents a double-sized element.
type bigElement255 [2 * SizeFp255]byte

// bigElement448 represents a double-sized element.
type bigElement448 [2 * SizeFp448]byte

// toString returns a hexadecimal string of a number stored in e (little-endian order)
func toString(e []byte) string {
	s := "0x"
	for i := len(e) - 1; i >= 0; i-- {
		s += fmt.Sprintf("%02x", e[i])
	}
	return s
}

// toBigInt converts a little-endian slice into a big-endian big.Int
func toBigInt(e []byte, size int) *big.Int {
	n := make([]byte, len(e))
	copy(n, e)
	for i := 0; i < size/2; i++ {
		t := n[size-i-1]
		n[size-i-1] = n[i]
		n[i] = t
	}
	return new(big.Int).SetBytes(n)
}

// String obtains a hexadecimal representation of e
func (e Element255) String() string { return toString(e[:]) }

// String obtains a hexadecimal representation of e
func (e Element448) String() string { return toString(e[:]) }

// BigInt gets a big integer with the current value of e, this value could be
// larger than p.
func (e Element255) BigInt() *big.Int { return toBigInt(e[:], SizeFp255) }

// BigInt gets a big integer with the current value of e, this value could be
// larger than p.
func (e Element448) BigInt() *big.Int { return toBigInt(e[:], SizeFp448) }
