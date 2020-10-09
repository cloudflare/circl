package group

import (
	"math/big"
)

// Element is a representation of a group element. It has two coordinates of
// *big.Int type.
type Element struct {
	c *Ciphersuite
	x *big.Int
	y *big.Int
}

// NewElement generates a new point.
func NewElement(c *Ciphersuite) *Element {
	p := &Element{c, new(big.Int), new(big.Int)}
	return p
}

// IsValid checks that the given Element is a valid curve point
func (p *Element) IsValid() bool {
	return p.c.curve.IsOnCurve(p.x, p.y)
}

// ScalarMult multiplies a Element by the provided Scalar value
func (p *Element) ScalarMult(s *Scalar) *Element {
	q := NewElement(p.c)
	q.x, q.y = p.c.curve.ScalarMult(p.x, p.y, s.Serialize())

	return q
}

// Add performs the addition operation on the calling Element object
// along with a separate Element provided as input
func (p *Element) Add(q *Element) *Element {
	r := NewElement(p.c)
	r.x, r.y = p.c.curve.Add(p.x, p.y, q.x, q.y)

	return r
}

// Neg performs the negation operation on the calling Element object
// TODO: check opaque to see what is needed
func (p *Element) Neg() *Element {
	r := NewElement(p.c)
	return r
}

// Serialize the Element into a byte slice.
// TODO: does not handle compressed points.. do we need it?
func (p *Element) Serialize() []byte {
	x, y := p.x.Bytes(), p.y.Bytes()

	// append zeroes to the front if the bytes are not filled up
	x = append(make([]byte, p.c.ByteLength()-len(x)), x...)
	y = append(make([]byte, p.c.ByteLength()-len(y)), y...)

	b := append(x, y...)
	tag := 4

	return append([]byte{byte(tag)}, b...)
}

// Deserialize an octet-string into a valid Element object.
func (p *Element) Deserialize(in []byte) {
	byteLength := p.c.ByteLength()

	p.x = new(big.Int).SetBytes(in[1 : byteLength+1])
	p.y = new(big.Int).SetBytes(in[byteLength+1:])
}

// Equal returns a bool indicating whether two Elements are equal.
func (p *Element) Equal(q *Element) bool {
	return (p.x.Cmp(q.x) == 0) && (p.y.Cmp(q.y) == 0)
}

// Scalar is an struct representing a field element
type Scalar struct {
	c *Ciphersuite
	x *big.Int
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
