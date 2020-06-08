package bls12381

import "github.com/cloudflare/circl/ecc/bls12381/ff"

type Gt struct{ g ff.Fp12 }

func (z *Gt) Sqr()    { z.g.Sqr(&z.g) }
func (z *Gt) SetOne() { z.g.SetOne() }
