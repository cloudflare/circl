package bls12381

import (
	"math/big"
)

const _NF1 = 6 // number of 64-bit words to represent an element in Fp.

// type fp [_NF1]uint64
type fp struct{ i big.Int }

func (z fp) String() string      { return "0x" + z.i.Text(16) }
func (z *fp) Set(x *fp)          { z.i.Set(&x.i) }
func (z *fp) SetString(s string) { z.i.SetString(s, 0) }
func (z *fp) SetUint64(n uint64) { z.i.SetUint64(n) }
func (z *fp) SetInt64(n int64)   { z.i.SetInt64(n) }
func (z *fp) SetZero()           { z.SetUint64(0) }
func (z *fp) SetOne()            { z.SetUint64(1) }
func (z *fp) IsZero() bool       { return z.i.Mod(&z.i, blsPrime).Sign() == 0 }
func (z *fp) IsEqual(x *fp) bool { return z.i.Cmp(&x.i) == 0 }
func (z *fp) Neg()               { z.i.Neg(&z.i).Mod(&z.i, blsPrime) }
func (z *fp) Add(x, y *fp)       { z.i.Add(&x.i, &y.i).Mod(&z.i, blsPrime) }
func (z *fp) Sub(x, y *fp)       { z.i.Sub(&x.i, &y.i).Mod(&z.i, blsPrime) }
func (z *fp) Mul(x, y *fp)       { z.i.Mul(&x.i, &y.i).Mod(&z.i, blsPrime) }
func (z *fp) Sqr(x *fp)          { z.i.Mul(&x.i, &x.i).Mod(&z.i, blsPrime) }
func (z *fp) Inv(x *fp)          { z.i.ModInverse(&x.i, blsPrime) }
