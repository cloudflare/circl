package ted448

import (
	"crypto/subtle"

	mlsb "github.com/cloudflare/circl/math/mlsbset"
)

const (
	// MLSBRecoding parameters
	fxT   = 448
	fxV   = 2
	fxW   = 3
	fx2w1 = 1 << (uint(fxW) - 1)
)

// ScalarBaseMult calculates R = kG, where G is the generator point.
func ScalarBaseMult(R *Point, k *Scalar) {
	m, err := mlsb.New(fxT, fxV, fxW)
	if err != nil {
		panic(err)
	}
	if m.IsExtended() {
		panic("not extended")
	}

	var k64, _k64, order64 scalar64
	k64.fromScalar(k)
	order64.fromScalar(&order)
	k64.cmov(&order64, uint64(k64.isZero()))

	isEven := 1 - int(k64[0]&0x1)
	_k64.sub(&order64, &k64)
	k64.cmov(&_k64, uint64(isEven))
	var scalar Scalar
	k64.toScalar(&scalar)

	c, err := m.Encode(scalar[:])
	if err != nil {
		panic(err)
	}

	gP := c.Exp(groupMLSB{})
	P := gP.(*Point)
	P.cneg(uint(isEven))
	*R = *P
}

type groupMLSB struct{}

func (e groupMLSB) ExtendedEltP() mlsb.EltP      { return nil }
func (e groupMLSB) Sqr(x mlsb.EltG)              { x.(*Point).Double() }
func (e groupMLSB) Mul(x mlsb.EltG, y mlsb.EltP) { x.(*Point).mixAddZ1(y.(*prePointAffine)) }
func (e groupMLSB) Identity() mlsb.EltG          { I := Identity(); return &I }
func (e groupMLSB) NewEltP() mlsb.EltP           { return &prePointAffine{} }
func (e groupMLSB) Lookup(a mlsb.EltP, v uint, s, u int32) {
	Tabj := &tabFixMult[v]
	P := a.(*prePointAffine)
	for k := range Tabj {
		P.cmov(&Tabj[k], uint(subtle.ConstantTimeEq(int32(k), u)))
	}
	P.cneg(int(s >> 31))
}
