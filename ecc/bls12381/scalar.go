package bls12381

// ScalarSize is the length in bytes of a Scalar.
const ScalarSize = 32

// Scalar represents an integer in little-endian order used for scalar multiplication.
type Scalar [ScalarSize]byte
