package group

import (
	"crypto/subtle"
	"errors"
	"math/big"
)

// Element is a representation of a group element.
type Element struct {
	c   *Ciphersuite
	x   *big.Int
	y   *big.Int
	com bool // use compression when serialiazing, be default set to true
}

// NewElement generates a new Element for the corresponding ciphersuite.
func NewElement(c *Ciphersuite) *Element {
	p := &Element{c, new(big.Int), new(big.Int), true}
	return p
}

// IsValid checks that the given Element is a valid curve point.
func (p *Element) IsValid() bool {
	return p.c.curve.IsOnCurve(p.x, p.y)
}

// ScalarMult multiplies a Element by the provided Scalar value.
func (p *Element) ScalarMult(s *Scalar) *Element {
	q := NewElement(p.c)
	q.x, q.y = p.c.curve.ScalarMult(p.x, p.y, s.Serialize())

	return q
}

// Add performs the addition operation on the calling Element object
// along with a separate Element provided as input.
func (p *Element) Add(q *Element) *Element {
	r := NewElement(p.c)
	r.x, r.y = p.c.curve.Add(p.x, p.y, q.x, q.y)

	return r
}

// Neg performs the negation operation on the calling Element object.
func (p *Element) Neg() *Element {
	xInv := new(big.Int).ModInverse(p.x, p.c.curve.Params().N)

	r := NewElement(p.c)
	r.x.Set(xInv)
	r.y.Set(p.y)

	return r
}

// Serialize the Element into a byte slice.
func (p *Element) Serialize() []byte {
	x, y := p.x.Bytes(), p.y.Bytes()

	// append zeroes to the front if the bytes are not filled up
	x = append(make([]byte, p.c.ByteLength()-len(x)), x...)
	y = append(make([]byte, p.c.ByteLength()-len(y)), y...)

	var b []byte
	var tag int
	if !p.com {
		b = append(x, y...)
		tag = 4
	} else {
		b = x
		sign := sgn0(p.y)
		// select correct tag
		e := int(equals(sign, one).Int64())
		tag = subtle.ConstantTimeSelect(e, 2, 3)
	}

	return append([]byte{byte(tag)}, b...)
}

// checkBytes checks that the number of bytes corresponds to the correct
// curve type and serialization tag that is present.
func isCompressed(in []byte, expLen int) (bool, error) {
	tag := in[0]
	com := false

	switch tag {
	case 2, 3:
		if expLen < len(in)-1 {
			return false, errors.New("error deserializing group element")
		}
		com = true
	case 4:
		if expLen*2 < len(in)-1 {
			return false, errors.New("error deserializing group element")
		}
	default:
		return false, errors.New("error deserializing group element")
	}

	return com, nil
}

// Deserialize a byte array into a valid Element object.
func (p *Element) Deserialize(in []byte) error {
	byteLen := p.c.ByteLength()

	com, err := isCompressed(in, byteLen)
	if err != nil {
		return err
	}

	if !com {
		p.x = new(big.Int).SetBytes(in[1 : byteLen+1])
		p.y = new(big.Int).SetBytes(in[byteLen+1:])

		if !p.IsValid() {
			return errors.New("invalid deserialization")
		}
	} else {
		order := p.c.curve.Params().P
		var y2 *big.Int
		x := new(big.Int).SetBytes(in[1:])

		x2 := new(big.Int).Exp(x, two, order)
		x2a := new(big.Int).Add(x2, big.NewInt(-3))
		x3 := new(big.Int).Mul(x2a, x)
		x3ab := new(big.Int).Add(x3, p.c.curve.Params().B)
		y2 = new(big.Int).Mod(x3ab, order)

		a1 := new(big.Int).Add(p.c.curve.Params().P, one)
		a2 := new(big.Int).ModInverse(big.NewInt(4), p.c.curve.Params().P)
		m := new(big.Int).Mul(a1, a2)
		sqrtExp := new(big.Int).Mod(m, p.c.curve.Params().P)

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

		p.com = true
	}

	return nil
}

// Equal returns a bool indicating whether two Elements are equal.
func (p *Element) Equal(q *Element) bool {
	return (p.x.Cmp(q.x) == 0) && (p.y.Cmp(q.y) == 0)
}

// Scalar is an struct representing a field element.
type Scalar struct {
	c *Ciphersuite
	x *big.Int
}

// NewScalar generates a new scalar.
func NewScalar(c *Ciphersuite) *Scalar {
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
