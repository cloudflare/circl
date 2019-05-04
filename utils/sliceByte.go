package utils

import (
	nonCryptoRand "crypto/rand"
	cryptoRand "math/rand"
)

// NonCryptoRand fills x with random numbers. This function is not cryptographic
// secure and cannot be used to generate keys.
func NonCryptoRand(x []byte) { _, _ = nonCryptoRand.Read(x) }

// CryptoRand fills x with random numbers. This function provides a uniform
// distribution of the output values.
func CryptoRand(x []byte) { _, _ = cryptoRand.Read(x) }
