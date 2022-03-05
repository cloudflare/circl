// Package group provides prime-order groups based on elliptic curves.
package group

import (
	"encoding"
	"errors"
	"io"
)

type Params struct {
	ElementLength           uint // Length in bytes of an element.
	CompressedElementLength uint // Length in bytes of a compressed element.
	ScalarLength            uint // Length in bytes of a scalar.
}

// Group represents a prime-order group based on elliptic curves.
type Group interface {
	Params() *Params // Params returns parameters for the group
	NewElement() Element
	NewScalar() Scalar
	Identity() Element
	Generator() Element
	Order() Scalar
	RandomElement(io.Reader) Element
	RandomScalar(io.Reader) Scalar
	RandomNonZeroScalar(io.Reader) Scalar
	HashToElement(data, dst []byte) Element
	HashToElementNonUniform(b, dst []byte) Element
	HashToScalar(data, dst []byte) Scalar
}

// Element represents an abstract element of a prime-order group.
type Element interface {
	Set(Element) Element
	Copy() Element
	IsIdentity() bool
	IsEqual(Element) bool
	Add(Element, Element) Element
	Dbl(Element) Element
	Neg(Element) Element
	Mul(Element, Scalar) Element
	MulGen(Scalar) Element
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	MarshalBinaryCompress() ([]byte, error)
}

// Scalar represents an integer scalar.
type Scalar interface {
	Set(Scalar) Scalar
	Copy() Scalar
	IsEqual(Scalar) bool
	SetUint64(uint64)
	Add(Scalar, Scalar) Scalar
	Sub(Scalar, Scalar) Scalar
	Mul(Scalar, Scalar) Scalar
	Neg(Scalar) Scalar
	Inv(Scalar) Scalar
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

var (
	ErrType            = errors.New("group: type mismatch")
	ErrInvalidDecoding = errors.New("group: invalid decoding")
)
