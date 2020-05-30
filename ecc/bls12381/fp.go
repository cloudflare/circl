package bls12381

import (
	"math/big"
)

const _NF1 = 6 // number of 64-bit words to represent an element in Fp.

// type fp [_NF1]uint64
type fp struct{ big.Int }

func (z fp) String() string      { return "0x" + z.Int.Text(16) }
func (z *fp) Set(x *fp)          { z.Int.Set(&x.Int) }
func (z *fp) SetZero()           { z.SetUint64(0) }
func (z *fp) SetOne()            { z.SetUint64(1) }
func (z *fp) IsZero() bool       { return z.Mod(&z.Int, blsPrime).Sign() == 0 }
func (z *fp) IsEqual(x *fp) bool { return z.Int.Cmp(&x.Int) == 0 }
func (z *fp) Neg()               { z.Int.Neg(&z.Int).Mod(&z.Int, blsPrime) }
func (z *fp) Add(x, y *fp)       { z.Int.Add(&x.Int, &y.Int).Mod(&z.Int, blsPrime) }
func (z *fp) Sub(x, y *fp)       { z.Int.Sub(&x.Int, &y.Int).Mod(&z.Int, blsPrime) }
func (z *fp) Mul(x, y *fp)       { z.Int.Mul(&x.Int, &y.Int).Mod(&z.Int, blsPrime) }
func (z *fp) Sqr(x *fp)          { z.Int.Mul(&x.Int, &x.Int).Mod(&z.Int, blsPrime) }
func (z *fp) Inv(x *fp)          { z.Int.ModInverse(&x.Int, blsPrime) }
