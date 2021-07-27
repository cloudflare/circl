package bls12381

import "github.com/cloudflare/circl/ecc/bls12381/ff"

// GtSize is the length in bytes of an element in Gt.
const GtSize = ff.URootSize

// Gt represents an element of the output (multiplicative) group of a pairing.
type Gt struct{ i ff.URoot }

func (z Gt) String() string               { return z.i.String() }
func (z *Gt) Set(x *Gt)                   { z.i.Set(&x.i) }
func (z *Gt) SetBytes(b []byte) error     { return z.i.SetBytes(b) }
func (z Gt) Bytes() []byte                { return z.i.Bytes() }
func (z *Gt) SetIdentity()                { z.i.SetIdentity() }
func (z Gt) IsEqual(x *Gt) bool           { return z.i.IsEqual(&x.i) == 1 }
func (z Gt) IsIdentity() bool             { i := &Gt{}; i.SetIdentity(); return z.IsEqual(i) }
func (z *Gt) Mul(x, y *Gt)                { z.i.Mul(&x.i, &y.i) }
func (z *Gt) Sqr(x *Gt)                   { z.i.Sqr(&x.i) }
func (z *Gt) Inv(x *Gt)                   { z.i.Inv(&x.i) }
func (z *Gt) ExpVarTime(x *Gt, n *Scalar) { z.i.ExpVarTime(&x.i, n.Bytes()) }
