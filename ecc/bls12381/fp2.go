package bls12381

import "fmt"

type fp2 [2]fp

func (z *fp2) String() string { return fmt.Sprintf("%v +i* %v", z[0], z[1]) }

func (z *fp2) Neg(x *fp2)    {}
func (z *fp2) Add(x, y *fp2) {}
func (z *fp2) Sub(x, y *fp2) {}
func (z *fp2) Mul(x, y *fp2) {}
func (z *fp2) Inv(x, y *fp2) {}
