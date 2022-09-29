// Package group provides prime-order groups based on elliptic curves.
package group

import (
	"encoding"
	"errors"
	"io"
	"math/big"
)

// Params stores the size in bytes of elements and scalars.
type Params struct {
	ElementLength           uint // Length in bytes of an element.
	CompressedElementLength uint // Length in bytes of a compressed element.
	ScalarLength            uint // Length in bytes of a scalar.
}

// Group represents an additive prime-order group based on elliptic curves.
type Group interface {
	Params() *Params // Params returns parameters for the group
	// Creates an element of the group set to the identity of the group.
	NewElement() Element
	// Creates a scalar of the group set to zero.
	NewScalar() Scalar
	// Creates an element of the group set to the identity of the group.
	Identity() Element
	// Creates an element of the group set to the generator of the group.
	Generator() Element
	// Returns a scalar set to the group order.
	Order() Scalar
	// RandomElement creates an element chosen at random (using randomness
	// from rnd) from the set of group elements. Use crypto/rand.Reader as
	// a cryptographically secure random number generator
	RandomElement(rnd io.Reader) Element
	// RandomScalar creates a scalar chosen at random (using randomness
	// from rnd) from the set of group scalars. Use crypto/rand.Reader as
	// a cryptographically secure random number generator
	RandomScalar(rnd io.Reader) Scalar
	// RandomNonZeroScalar creates a scalar chosen at random (using randomness
	// from rnd) from the set of group scalars. Use crypto/rand.Reader as
	// a cryptographically secure random number generator. It is guaranteed
	// the scalar is not zero.
	RandomNonZeroScalar(io.Reader) Scalar
	// HashToElement hashes a message (msg) using a domain separation string
	// (dst) producing a group element with uniform distribution.
	HashToElement(msg, dst []byte) Element
	// HashToElementNonUniform hashes a message (msg) using a domain separation
	// string (dst) producing a group element with nonuniform distribution.
	HashToElementNonUniform(msg, dst []byte) Element
	// HashToScalar hashes a message (msg) using a domain separation string
	// (dst) producing a group scalar with uniform distribution.
	HashToScalar(msg, dst []byte) Scalar
}

// Element represents an element of a prime-order group.
type Element interface {
	// Returns the group that the element belongs to.
	Group() Group
	// Set the receiver to x, and returns the receiver.
	Set(x Element) Element
	// Copy returns a new element equal to the receiver.
	Copy() Element
	// IsIdentity returns true if the receiver is the identity element of the
	// group.
	IsIdentity() bool
	// IsEqual returns true if the receiver is equal to x.
	IsEqual(x Element) bool
	// CMov sets the receiver to x if b=1; the receiver is unmodified if b=0;
	// otherwise panics if b is not 0 or 1. In all the cases, it returns the
	// receiver.
	CMov(b int, x Element) Element
	// CSelect sets the receiver to x if b=1; sets the receiver to y if b=0;
	// otherwise panics if b is not 0 or 1. In all the cases, it returns the
	// receiver.
	CSelect(b int, x, y Element) Element
	// Add sets the receiver to x + y, and returns the receiver.
	Add(x, y Element) Element
	// Dbl sets the receiver to 2 * x, and returns the receiver.
	Dbl(x Element) Element
	// Neg sets the receiver to -x, and returns the receiver.
	Neg(x Element) Element
	// Mul sets the receiver to s * x, and returns the receiver.
	Mul(x Element, s Scalar) Element
	// MulGen sets the receiver to s * Generator(), and returns the receiver.
	MulGen(s Scalar) Element
	// BinaryMarshaler returns a byte representation of the element.
	encoding.BinaryMarshaler
	// BinaryUnmarshaler recovers an element from a byte representation
	// produced either by encoding.BinaryMarshaler or MarshalBinaryCompress.
	encoding.BinaryUnmarshaler
	// MarshalBinaryCompress returns a byte representation of an elment in a
	// compact form whenever the group supports it; otherwise, returns the
	// same byte representation produced by encoding.BinaryMarshaler.
	MarshalBinaryCompress() ([]byte, error)
}

// Scalar represents a scalar of a prime-order group.
type Scalar interface {
	// Returns the group that the scalar belongs to.
	Group() Group
	// Set the receiver to x, and returns the receiver.
	Set(x Scalar) Scalar
	// Copy returns a new scalar equal to the receiver.
	Copy() Scalar
	// IsZero returns true if the receiver is equal to zero.
	IsZero() bool
	// IsEqual returns true if the receiver is equal to x.
	IsEqual(x Scalar) bool
	// SetUint64 sets the receiver to x, and returns the receiver.
	SetUint64(x uint64) Scalar
	// SetBigInt sets the receiver to x, and returns the receiver.
	// Warning: operations on big.Int are not constant time. Do not use them
	// for cryptography unless you're sure it's safe in your use-case.
	SetBigInt(b *big.Int) Scalar
	// CMov sets the receiver to x if b=1; the receiver is unmodified if b=0;
	// otherwise panics if b is not 0 or 1. In all the cases, it returns the
	// receiver.
	CMov(b int, x Scalar) Scalar
	// CSelect sets the receiver to x if b=1; sets the receiver to y if b=0;
	// otherwise panics if b is not 0 or 1. In all the cases, it returns the
	// receiver.
	CSelect(b int, x, y Scalar) Scalar
	// Add sets the receiver to x + y, and returns the receiver.
	Add(x, y Scalar) Scalar
	// Sub sets the receiver to x - y, and returns the receiver.
	Sub(x, y Scalar) Scalar
	// Mul sets the receiver to x * y, and returns the receiver.
	Mul(x, y Scalar) Scalar
	// Neg sets the receiver to -x, and returns the receiver.
	Neg(x Scalar) Scalar
	// Inv sets the receiver to 1/x, and returns the receiver.
	Inv(x Scalar) Scalar
	// BinaryMarshaler returns a byte representation of the scalar.
	encoding.BinaryMarshaler
	// BinaryUnmarshaler recovers a scalar from a byte representation produced
	// by encoding.BinaryMarshaler.
	encoding.BinaryUnmarshaler
}

var (
	ErrType      = errors.New("group: type mismatch")
	ErrUnmarshal = errors.New("group: error unmarshaling")
	ErrSelector  = errors.New("group: selector must be 0 or 1")
)
