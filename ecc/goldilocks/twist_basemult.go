package goldilocks

import (
	"crypto/subtle"
	"fmt"
	"math/big"

	fp "github.com/cloudflare/circl/math/fp448"
	"github.com/cloudflare/circl/math/mlsbset"
	mlsb "github.com/cloudflare/circl/math/mlsbset"
)

const (
	// MLSBRecoding parameters
	fxT   = 448
	fxV   = 2
	fxW   = 3
	fx2w1 = 1 << (uint(fxW) - 1)
)

// ScalarBaseMult returns kG where G is the generator point.
func (e twistCurve) ScalarBaseMult(k []byte) *twistPoint {
	m, err := mlsb.New(fxT, fxV, fxW)
	if err != nil {
		panic(err)
	}
	fmt.Printf("m: %v\n", m)
	if m.IsExtended() {
		panic("not extended")
	}

	isEven := k[0] & 0x1
	cNegate(k, int(isEven))

	c, err := m.Encode(k)
	if err != nil {
		panic(err)
	}
	// bigP := c.Exp(zzAdd{m.GetParams()})
	// fmt.Printf("k: %v\n", bigP.(*big.Int).Text(16))

	gP := c.Exp(groupMLSB{})
	P := gP.(*twistPoint)
	P.cneg(uint(isEven))
	return P
}

type zzAdd struct{ set mlsbset.Params }

func (zzAdd) Identity() mlsbset.EltG { return big.NewInt(0) }
func (zzAdd) NewEltP() mlsbset.EltP  { return new(big.Int) }
func (zzAdd) Sqr(x mlsbset.EltG) {
	a := x.(*big.Int)
	a.Add(a, a)
}
func (zzAdd) Mul(x mlsbset.EltG, y mlsbset.EltP) {
	a := x.(*big.Int)
	b := y.(*big.Int)
	a.Add(a, b)
}
func (z zzAdd) ExtendedEltP() mlsbset.EltP {
	a := big.NewInt(1)
	a.Lsh(a, z.set.W*z.set.D)
	return a
}
func (z zzAdd) Lookup(x mlsbset.EltP, idTable uint, sgnElt int32, idElt int32) {
	a := x.(*big.Int)
	a.SetInt64(1)
	a.Lsh(a, z.set.E*idTable) // 2^(e*v)
	sum := big.NewInt(0)
	for i := int(z.set.W - 2); i >= 0; i-- {
		ui := big.NewInt(int64((idElt >> uint(i)) & 0x1))
		sum.Add(sum, ui)
		sum.Lsh(sum, z.set.D)
	}
	sum.Add(sum, big.NewInt(1))
	a.Mul(a, sum)
	if sgnElt == -1 {
		a.Neg(a)
	}
}

type groupMLSB struct{}

func (e groupMLSB) ExtendedEltP() mlsb.EltP      { return nil }
func (e groupMLSB) Sqr(x mlsb.EltG)              { x.(*twistPoint).Double() }
func (e groupMLSB) Mul(x mlsb.EltG, y mlsb.EltP) { x.(*twistPoint).mixAdd(y.(*preTwistPoint)) }
func (e groupMLSB) Identity() mlsb.EltG          { return twistCurve{}.Identity() }
func (e groupMLSB) NewEltP() mlsb.EltP           { return &preTwistPoint{} }
func (e groupMLSB) Lookup(a mlsb.EltP, v uint, s, u int32) {
	Tabj := &tabFixMult[v]
	P := a.(*preTwistPoint)
	for k := range Tabj {
		P.cmov(&Tabj[k], subtle.ConstantTimeEq(int32(k), int32(u)))
	}
	P.cneg(int(s >> 31))
}

type preTwistPoint struct{ addYX, subYX, dt2 fp.Elt }

func (P *preTwistPoint) neg() {
	P.addYX, P.subYX = P.subYX, P.addYX
	fp.Neg(&P.dt2, &P.dt2)
}

func (P *preTwistPoint) cneg(b int) {
	t := &fp.Elt{}
	fp.Cswap(&P.addYX, &P.subYX, uint(b))
	fp.Neg(t, &P.dt2)
	fp.Cmov(&P.dt2, t, uint(b))
}

func (P *preTwistPoint) cmov(Q *preTwistPoint, b int) {
	fp.Cmov(&P.addYX, &Q.addYX, uint(b))
	fp.Cmov(&P.subYX, &Q.subYX, uint(b))
	fp.Cmov(&P.dt2, &Q.dt2, uint(b))
}
