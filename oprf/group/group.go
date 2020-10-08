package group

import (
	"math/big"
)

// Point is a representation of a group element. It has two coordinates of
// *big.Int type.
type Point struct {
	c *Ciphersuite
	x *big.Int
	y *big.Int
}

// Element is the interface that represents points in a given
// Ciphersuite instantiation.
type element interface { //nolint:deadcode
	// Returns a bool indicating that the Point is valid
	IsValid() bool

	// Returns a bool indicating that the Point is the identity
	IsIdentity() bool

	// Performs a scalar multiplication of the Point with some scalar
	// input
	ScalarMult(*Scalar) *Point

	// Performs the addition operation on the calling Point object
	// along with a separate Point provided as input
	Add(*Point) *Point

	// Performs the negation operation on the calling Point object
	Neg() *Point

	// Serializes the Point into a byte slice
	Serialize() ([]byte, error)

	// Attempts to deserialize a byte slice into a Point
	Deserialize([]byte) error

	// Returns a bool indicating whether two Points are equal
	Equal(*Point) bool
}

// NewPoint generates a new point.
func NewPoint(c *Ciphersuite) *Point {
	p := &Point{c, new(big.Int), new(big.Int)}
	return p
}

// IsValid checks that the given Point is a valid curve point
func (p *Point) IsValid() bool {
	return p.c.curve.IsOnCurve(p.x, p.y)
}

// ScalarMult multiplies a Point by the provided Scalar value
func (p *Point) ScalarMult(s *Scalar) *Point {
	q := NewPoint(p.c)
	q.x, q.y = p.c.curve.ScalarMult(p.x, p.y, s.Serialize())

	return q
}

// Add performs the addition operation on the calling Point object
// along with a separate Point provided as input
func (p *Point) Add(q *Point) *Point {
	r := NewPoint(p.c)
	r.x, r.y = p.c.curve.Add(p.x, p.y, q.x, q.y)

	return r
}

// Neg performs the negation operation on the calling Point object
// TODO: check opaque to see what is needed
func (p *Point) Neg() *Point {
	r := NewPoint(p.c)
	return r
}

// Serialize the Point into a byte slice.
// TODO: does not handle compressed points.. do we need it?
func (p *Point) Serialize() []byte {
	x, y := p.x.Bytes(), p.y.Bytes()

	// append zeroes to the front if the bytes are not filled up
	x = append(make([]byte, p.c.ByteLength()-len(x)), x...)
	y = append(make([]byte, p.c.ByteLength()-len(y)), y...)

	b := append(x, y...)
	tag := 4

	return append([]byte{byte(tag)}, b...)
}

// Deserialize an octet-string into a valid Point object.
func (p *Point) Deserialize(in []byte) {
	byteLength := p.c.ByteLength()

	p.x = new(big.Int).SetBytes(in[1 : byteLength+1])
	p.y = new(big.Int).SetBytes(in[byteLength+1:])
}

// Equal returns a bool indicating whether two Points are equal.
func (p *Point) Equal(q *Point) bool {
	return (p.x.Cmp(q.x) == 0) && (p.y.Cmp(q.y) == 0)
}

// Scalar is an struct representing a field element
type Scalar struct {
	c *Ciphersuite
	x *big.Int
}

// scalar is the interface that represents scalars in a given
// Ciphersuite instantiation.
type scalar interface { //nolint:deadcode
	// Sets the Scalar to its multiplicative inverse.
	Inv(*Scalar) *Scalar

	// Serializes an Scalar into a byte slice.
	Serialize() []byte

	// Attempts to deserialize a byte slice into an Scalar.
	Deserialize([]byte)
}

// NewScalar generates a new scalar.
func NewScalar(c *Ciphersuite) *Scalar {
	s := &Scalar{c, new(big.Int)}
	return s
}

// Inv sets the Scalar to its multiplicative inverse.
func (s *Scalar) Inv() *Scalar {
	n := s.c.Order()
	inv := new(big.Int).ModInverse(s.x, n.x)

	rInv := NewScalar(s.c)
	rInv.x.Set(inv)

	return rInv
}

// Serialize the Scalar into a byte slice.
func (s *Scalar) Serialize() []byte {
	l := s.c.ByteLength()
	bytes := s.x.Bytes()
	if len(bytes) < l {
		arr := make([]byte, l-len(bytes))
		bytes = append(arr, bytes...)
	}

	return bytes
}

// Deserialize an octet-string into a valid Scalar object.
func (s *Scalar) Deserialize(in []byte) {
	byteLength := s.c.ByteLength()

	s.x = new(big.Int).SetBytes(in[1 : byteLength+1])
}
