package bls12381

import "github.com/cloudflare/circl/internal/conv"

const _NF1 = 6 // number of 64-bit words to represent an element in Fp.

type fp [_NF1]uint64

func (z *fp) String() string { return conv.Uint64Le2Hex(z[:]) }

func (z *fp) SetZero()     {}
func (z *fp) SetOne()      {}
func (z *fp) IsZero() bool { return false }
func (z *fp) Neg()         {}
func (z *fp) Add(x, y *fp) {}
func (z *fp) Sub(x, y *fp) {}
func (z *fp) Mul(x, y *fp) {}
func (z *fp) Sqr(x *fp)    {}
func (z *fp) Inv(x *fp)    {}
