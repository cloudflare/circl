package goldilocks

import (
	"fmt"

	fp "github.com/cloudflare/circl/math/fp448"
)

type twistPoint struct{ x, y, z, ta, tb fp.Elt }

func (P *twistPoint) String() string {
	return fmt.Sprintf("x: %v\ny: %v\nz: %v\nta: %v\ntb: %v", P.x, P.y, P.z, P.ta, P.tb)
}

// TODO remove this func
func (P *twistPoint) ToAffine() {
	fp.Inv(&P.z, &P.z)       // 1/z
	fp.Mul(&P.x, &P.x, &P.z) // x/z
	fp.Mul(&P.y, &P.y, &P.z) // y/z
	fp.Modp(&P.x)
	fp.Modp(&P.y)
	fp.SetOne(&P.z)
	P.ta = P.x
	P.tb = P.y
}

// cneg conditionally negates the point if b=1.
func (P *twistPoint) cneg(b uint) {
	t := &fp.Elt{}
	fp.Neg(t, &P.x)
	fp.Cmov(&P.x, t, b)
	fp.Neg(t, &P.ta)
	fp.Cmov(&P.ta, t, b)
}

// Double updates P with 2P.
func (P *twistPoint) Double() {
	Px, Py, Pz, Pta, Ptb := &P.x, &P.y, &P.z, &P.ta, &P.tb
	a, b, c, e, f, g, h := Px, Py, Pz, Pta, Px, Py, Ptb
	fp.Add(e, Px, Py) // x+y
	fp.Sqr(a, Px)     // A = x^2
	fp.Sqr(b, Py)     // B = y^2
	fp.Sqr(c, Pz)     // z^2
	fp.Add(c, c, c)   // C = 2*z^2
	fp.Add(h, a, b)   // H = A+B
	fp.Sqr(e, e)      // (x+y)^2
	fp.Sub(e, e, h)   // E = (x+y)^2-A-B
	fp.Sub(g, b, a)   // G = B-A
	fp.Sub(f, c, g)   // F = C-G
	fp.Mul(Pz, f, g)  // Z = F * G
	fp.Mul(Px, e, f)  // X = E * F
	fp.Mul(Py, g, h)  // Y = G * H, T = E * H
}

func (P *twistPoint) mixAdd(Q *preTwistPoint) {
	fp.Add(&P.z, &P.z, &P.z) // D = 2*z1
	P.coreAddition(Q)
}

// coreAddition calculates P=P+Q for curves with A=-1
func (P *twistPoint) coreAddition(Q *preTwistPoint) {
	Px, Py, Pz, Pta, Ptb := &P.x, &P.y, &P.z, &P.ta, &P.tb
	addYX2, subYX2, dt2 := &Q.addYX, &Q.subYX, &Q.dt2
	a, b, c, d, e, f, g, h := Px, Py, &fp.Elt{}, Pz, Pta, Px, Py, Ptb
	fp.Mul(c, Pta, Ptb)  // t1 = ta*tb
	fp.Sub(h, Py, Px)    // y1-x1
	fp.Add(b, Py, Px)    // y1+x1
	fp.Mul(a, h, subYX2) // A = (y1-x1)*(y2-x2)
	fp.Mul(b, b, addYX2) // B = (y1+x1)*(y2+x2)
	fp.Mul(c, c, dt2)    // C = 2*D*t1*t2
	fp.Sub(e, b, a)      // E = B-A
	fp.Add(h, b, a)      // H = B+A
	fp.Sub(f, d, c)      // F = D-C
	fp.Add(g, d, c)      // G = D+C
	fp.Mul(Pz, f, g)     // Z = F * G
	fp.Mul(Px, e, f)     // X = E * F
	fp.Mul(Py, g, h)     // Y = G * H, T = E * H
}

type pointR2 struct {
	preTwistPoint
	z2 fp.Elt
}

func (P *twistPoint) add(Q *pointR2) {
	fp.Mul(&P.z, &P.z, &Q.z2) // D = 2*z1*z2
	P.coreAddition(&Q.preTwistPoint)
}

func (P *twistPoint) oddMultiples(T []pointR2) {
	var R pointR2
	n := len(T)
	T[0].fromR1(P)
	_2P := *P
	_2P.Double()
	R.fromR1(&_2P)
	for i := 1; i < n; i++ {
		P.add(&R)
		T[i].fromR1(P)
	}
}

func (P *pointR2) fromR1(Q *twistPoint) {
	fp.Add(&P.addYX, &Q.y, &Q.x)
	fp.Sub(&P.subYX, &Q.y, &Q.x)
	fp.Mul(&P.dt2, &Q.ta, &Q.tb)
	fp.Mul(&P.dt2, &P.dt2, &paramD) // <-fix this D (should be the D from the twist)
	fp.Add(&P.dt2, &P.dt2, &P.dt2)
	fp.Add(&P.z2, &Q.z, &Q.z)
}
