package bls12381

import "github.com/cloudflare/circl/ecc/bls12381/ff"

type Gt ff.Fp12

func (z *Gt) SetOne()              { (*ff.Fp12)(z).SetOne() }
func (z *Gt) IsEqual(x *Gt) bool   { return (*ff.Fp12)(z).IsEqual((*ff.Fp12)(x)) }
func (z *Gt) Exp(x *Gt, n *Scalar) { (*ff.Fp12)(z).Exp((*ff.Fp12)(x), n.Bytes()) }
func (z *Gt) Mul(x, y *Gt)         { (*ff.Fp12)(z).Mul((*ff.Fp12)(x), (*ff.Fp12)(y)) }
