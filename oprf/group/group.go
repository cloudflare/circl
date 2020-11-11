package group

import (
	"crypto/elliptic"
	"crypto/subtle"
	"errors"
	"math/big"
)

// Element is a representation of a group element.
type Element struct {
	c elliptic.Curve
	x *big.Int
	y *big.Int
}

// NewElement generates a new Element for the corresponding ciphersuite.
func NewElement(c elliptic.Curve) *Element {
	p := &Element{c, new(big.Int), new(big.Int)}
	return p
}

// IsValid checks that the given Element is a valid curve point.
func (p *Element) IsValid() bool {
	return p.c.IsOnCurve(p.x, p.y)
}

// ScalarBaseMult multiplies the Generator by the provided Scalar value.
// The provided 'p' should be equal to the generator.
func (p *Element) ScalarBaseMult(s *Scalar) *Element {
	g := &Element{p.c, p.c.Params().Gx, p.c.Params().Gy}
	if !(p.Equal(g)) {
		return nil
	}

	q := NewElement(p.c)
	q.x, q.y = p.c.ScalarBaseMult(s.Serialize())

	return q
}

// ScalarMult multiplies a Element by the provided Scalar value.
func (p *Element) ScalarMult(s *Scalar) *Element {
	q := NewElement(p.c)
	q.x, q.y = p.c.ScalarMult(p.x, p.y, s.Serialize())

	return q
}

// Add performs the addition operation on the calling Element object
// along with a separate Element provided as input.
func (p *Element) Add(q *Element) *Element {
	r := NewElement(p.c)
	r.x, r.y = p.c.Add(p.x, p.y, q.x, q.y)

	return r
}

// Neg performs the negation operation on the calling Element object.
func (p *Element) Neg() *Element {
	xInv := new(big.Int).ModInverse(p.x, p.c.Params().N)

	r := NewElement(p.c)
	r.x.Set(xInv)
	r.y.Set(p.y)

	return r
}

// Serialize the Element into a byte slice.
func (p *Element) Serialize() []byte {
	x := p.x.Bytes()
	// append zeroes to the front if the bytes are not filled up.
	x = append(make([]byte, ((p.c.Params().BitSize+7)/8)-len(x)), x...)

	var b []byte
	var tag int
	b = x
	sign := sgn0(p.y)
	// select correct tag.
	e := int(equals(sign, one).Int64())
	tag = subtle.ConstantTimeSelect(e, 2, 3)

	return append([]byte{byte(tag)}, b...)
}

// Deserialize a byte array into a valid Element object.
func (p *Element) Deserialize(in []byte) error {
	order := p.c.Params().P
	var y2 *big.Int
	x := new(big.Int).SetBytes(in[1:])

	x2 := new(big.Int).Exp(x, two, order)
	x2a := new(big.Int).Add(x2, big.NewInt(-3))
	x3 := new(big.Int).Mul(x2a, x)
	x3ab := new(big.Int).Add(x3, p.c.Params().B)
	y2 = new(big.Int).Mod(x3ab, order)

	a1 := new(big.Int).Add(p.c.Params().P, one)
	a2 := new(big.Int).ModInverse(big.NewInt(4), p.c.Params().P)
	m := new(big.Int).Mul(a1, a2)
	sqrtExp := new(big.Int).Mod(m, p.c.Params().P)

	// construct y coordinate with correct sign
	y := new(big.Int).Exp(y2, sqrtExp, order)
	parity := equals(big.NewInt(int64(in[0])), two)
	yParity := equals(sgn0(y), one)
	y = cMov(new(big.Int).Mul(y, minusOne), y, equals(parity, yParity))

	p.x = new(big.Int).Mod(x, order)
	p.y = new(big.Int).Mod(y, order)

	if !p.IsValid() {
		return errors.New("invalid deserialization")
	}

	return nil
}

// Equal returns a bool indicating whether two Elements are equal.
func (p *Element) Equal(q *Element) bool {
	return (p.x.Cmp(q.x) == 0) && (p.y.Cmp(q.y) == 0)
}

// Scalar is an struct representing a field element.
type Scalar struct {
	c elliptic.Curve
	x *big.Int
}

// NewScalar generates a new scalar.
func NewScalar(c elliptic.Curve) *Scalar {
	s := &Scalar{c, new(big.Int)}
	return s
}

// Set sets the scalar to a value.
func (s *Scalar) Set(x []byte) *Scalar {
	s.x.SetBytes(x)
	return s
}

// Inv sets the Scalar to its multiplicative inverse.
func (s *Scalar) Inv() *Scalar {
	n := s.c.Params().N
	inv := new(big.Int).ModInverse(s.x, n)

	rInv := NewScalar(s.c)
	rInv.x.Set(inv)

	return rInv
}

// Serialize the Scalar into a byte slice.
func (s *Scalar) Serialize() []byte {
	return s.x.Bytes()
}

// Deserialize an octet-string into a valid Scalar object.
func (s *Scalar) Deserialize(in []byte) {
	byteLength := (s.c.Params().BitSize + 7) / 8
	s.x = new(big.Int).SetBytes(in[:byteLength])
}
