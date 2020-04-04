package goldilocks

import (
	"crypto/subtle"

	fp "github.com/cloudflare/circl/math/fp448"
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
func (e twistCurve) ScalarBaseMult(k *Scalar) *twistPoint {
	m, err := mlsb.New(fxT, fxV, fxW)
	if err != nil {
		panic(err)
	}
	if m.IsExtended() {
		panic("not extended")
	}

	minusK := *k
	isEven := 1 - int(k[0]&0x1)
	minusK.Neg()
	subtle.ConstantTimeCopy(isEven, k[:], minusK[:])
	c, err := m.Encode(k[:])
	if err != nil {
		panic(err)
	}

	gP := c.Exp(groupMLSB{})
	P := gP.(*twistPoint)
	P.cneg(uint(isEven))
	return P
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
