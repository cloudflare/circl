package bls12381

import "github.com/cloudflare/circl/ecc/bls12381/ff"

// GtSize is the length in bytes of an element in Gt.
const GtSize = ff.Fp12Size

// Gt represents an element of the output group of a pairing.
type Gt ff.Fp12

func (z Gt) String() string           { return (ff.Fp12)(z).String() }
func (z *Gt) Set(x *Gt)               { (*ff.Fp12)(z).Set((*ff.Fp12)(x)) }
func (z *Gt) SetBytes(b []byte) error { return (*ff.Fp12)(z).SetBytes(b) }
func (z Gt) Bytes() []byte            { return (ff.Fp12)(z).Bytes() }
func (z *Gt) SetIdentity()            { (*ff.Fp12)(z).SetOne() }
func (z Gt) IsIdentity() bool         { i := &Gt{}; i.SetIdentity(); return z.IsEqual(i) }
func (z Gt) IsEqual(x *Gt) bool       { return (ff.Fp12)(z).IsEqual((*ff.Fp12)(x)) }
func (z *Gt) Exp(x *Gt, n *Scalar)    { (*ff.Fp12)(z).Exp((*ff.Fp12)(x), n.Bytes()) }
func (z *Gt) Mul(x, y *Gt)            { (*ff.Fp12)(z).Mul((*ff.Fp12)(x), (*ff.Fp12)(y)) }
func (z *Gt) Sqr(x *Gt)               { (*ff.Fp12)(z).Sqr((*ff.Fp12)(x)) }
func (z *Gt) Inv(x *Gt)               { (*ff.Fp12)(z).Inv((*ff.Fp12)(x)) }
