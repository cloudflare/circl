package ff

import "math/big"

type Fp struct{ i big.Int }

func (z Fp) String() string           { return "0x" + z.i.Text(16) }
func (z *Fp) Set(x *Fp)               { z.i.Set(&x.i) }
func (z *Fp) SetString(s string) bool { _, ok := z.i.SetString(s, 0); return ok }
func (z *Fp) SetUint64(n uint64)      { z.i.SetUint64(n) }
func (z *Fp) SetInt64(n int64)        { z.i.SetInt64(n) }
func (z *Fp) SetZero()                { z.SetUint64(0) }
func (z *Fp) SetOne()                 { z.SetUint64(1) }
func (z *Fp) IsZero() bool            { return z.i.Mod(&z.i, blsPrime).Sign() == 0 }
func (z *Fp) IsEqual(x *Fp) bool      { return z.i.Cmp(&x.i) == 0 }
func (z *Fp) Neg()                    { z.i.Neg(&z.i).Mod(&z.i, blsPrime) }
func (z *Fp) Add(x, y *Fp)            { z.i.Add(&x.i, &y.i).Mod(&z.i, blsPrime) }
func (z *Fp) Sub(x, y *Fp)            { z.i.Sub(&x.i, &y.i).Mod(&z.i, blsPrime) }
func (z *Fp) Mul(x, y *Fp)            { z.i.Mul(&x.i, &y.i).Mod(&z.i, blsPrime) }
func (z *Fp) Sqr(x *Fp)               { z.i.Mul(&x.i, &x.i).Mod(&z.i, blsPrime) }
func (z *Fp) Inv(x *Fp)               { z.i.ModInverse(&x.i, blsPrime) }
func (z *Fp) Sqrt(x *Fp) (isQR bool)  { r := z.i.ModSqrt(&x.i, blsPrime); return r != nil }
