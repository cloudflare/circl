package group

import (
	"crypto"
	_ "crypto/sha512"
	"fmt"
	"io"

	r255 "github.com/bwesterb/go-ristretto"
	"github.com/cloudflare/circl/expander"
)

// Ristretto255 is a quotient group generated from edwards25519 curve.
var Ristretto255 Group = ristrettoGroup{}

type ristrettoGroup struct{}

func (g ristrettoGroup) String() string {
	return "ristretto255"
}

func (g ristrettoGroup) Params() *Params {
	return &Params{32, 32, 32}
}

type ristrettoElement struct {
	p r255.Point
}

type ristrettoScalar struct {
	s r255.Scalar
}

func (g ristrettoGroup) NewElement() Element {
	return g.Identity()
}

func (g ristrettoGroup) NewScalar() Scalar {
	return &ristrettoScalar{
		s: r255.Scalar{},
	}
}

func (g ristrettoGroup) Identity() Element {
	var zero r255.Point
	zero.SetZero()
	return &ristrettoElement{
		p: zero,
	}
}

func (g ristrettoGroup) Generator() Element {
	var base r255.Point
	base.SetBase()
	return &ristrettoElement{
		p: base,
	}
}

func (g ristrettoGroup) Order() Scalar {
	q := r255.Scalar{
		0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de,
		0x00000000, 0x00000000, 0x00000000, 0x10000000,
	}
	return &ristrettoScalar{
		s: q,
	}
}

func (g ristrettoGroup) RandomElement(r io.Reader) Element {
	var x r255.Point
	x.Rand()
	return &ristrettoElement{
		p: x,
	}
}

func (g ristrettoGroup) RandomScalar(io.Reader) Scalar {
	var x r255.Scalar
	x.Rand()
	return &ristrettoScalar{
		s: x,
	}
}

func (g ristrettoGroup) RandomNonZeroScalar(io.Reader) Scalar {
	var s r255.Scalar
	for {
		s.Rand()
		if s.IsNonZeroI() == 1 {
			return &ristrettoScalar{s}
		}
	}
}

func (g ristrettoGroup) HashToElementNonUniform(b, dst []byte) Element {
	return g.HashToElement(b, dst)
}

func (g ristrettoGroup) HashToElement(msg, dst []byte) Element {
	xmd := expander.NewExpanderMD(crypto.SHA512, dst)
	data := xmd.Expand(msg, 64)
	e := g.NewElement()
	e.(*ristrettoElement).p.Derive(data)
	return e
}

func (g ristrettoGroup) HashToScalar(msg, dst []byte) Scalar {
	s := g.NewScalar()
	s.(*ristrettoScalar).s.Derive(msg)
	return s
}

func (e *ristrettoElement) IsIdentity() bool {
	var zero r255.Point
	zero.SetZero()
	return e.p.Equals(&zero)
}

func (e *ristrettoElement) IsEqual(x Element) bool {
	return e.p.Equals(&x.(*ristrettoElement).p)
}

func (e *ristrettoElement) Set(x Element) Element {
	e.p.Set(&x.(*ristrettoElement).p)
	return e
}

func (e *ristrettoElement) Copy() Element {
	return &ristrettoElement{*new(r255.Point).Set(&e.p)}
}

func (e *ristrettoElement) Add(x Element, y Element) Element {
	e.p.Add(&x.(*ristrettoElement).p, &y.(*ristrettoElement).p)
	return e
}

func (e *ristrettoElement) Dbl(x Element) Element {
	return e.Add(x, x)
}

func (e *ristrettoElement) Neg(x Element) Element {
	e.p.Neg(&x.(*ristrettoElement).p)
	return e
}

func (e *ristrettoElement) Mul(x Element, y Scalar) Element {
	e.p.ScalarMult(&x.(*ristrettoElement).p, &y.(*ristrettoScalar).s)
	return e
}

func (e *ristrettoElement) MulGen(x Scalar) Element {
	e.p.ScalarMultBase(&x.(*ristrettoScalar).s)
	return e
}

func (e *ristrettoElement) MarshalBinaryCompress() ([]byte, error) {
	return e.p.MarshalBinary()
}

func (e *ristrettoElement) MarshalBinary() ([]byte, error) {
	return e.p.MarshalBinary()
}

func (e *ristrettoElement) UnmarshalBinary(data []byte) error {
	return e.p.UnmarshalBinary(data)
}

func (s *ristrettoScalar) String() string     { return fmt.Sprintf("0x%x", s.s.Bytes()) }
func (s *ristrettoScalar) SetUint64(n uint64) { s.s.SetUint64(n) }

func (s *ristrettoScalar) IsEqual(x Scalar) bool {
	return s.s.Equals(&x.(*ristrettoScalar).s)
}

func (s *ristrettoScalar) Set(x Scalar) Scalar {
	s.s.Set(&x.(*ristrettoScalar).s)
	return s
}

func (s *ristrettoScalar) Copy() Scalar {
	return &ristrettoScalar{*new(r255.Scalar).Set(&s.s)}
}

func (s *ristrettoScalar) Add(x Scalar, y Scalar) Scalar {
	s.s.Add(&x.(*ristrettoScalar).s, &y.(*ristrettoScalar).s)
	return s
}

func (s *ristrettoScalar) Sub(x Scalar, y Scalar) Scalar {
	s.s.Sub(&x.(*ristrettoScalar).s, &y.(*ristrettoScalar).s)
	return s
}

func (s *ristrettoScalar) Mul(x Scalar, y Scalar) Scalar {
	s.s.Mul(&x.(*ristrettoScalar).s, &y.(*ristrettoScalar).s)
	return s
}

func (s *ristrettoScalar) Neg(x Scalar) Scalar {
	s.s.Neg(&x.(*ristrettoScalar).s)
	return s
}

func (s *ristrettoScalar) Inv(x Scalar) Scalar {
	s.s.Inverse(&x.(*ristrettoScalar).s)
	return s
}

func (s *ristrettoScalar) MarshalBinary() ([]byte, error) {
	return s.s.MarshalBinary()
}

func (s *ristrettoScalar) UnmarshalBinary(data []byte) error {
	return s.s.UnmarshalBinary(data)
}
