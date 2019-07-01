package ed25519

import fp "github.com/cloudflare/circl/math/fp25519"

type pointR1 struct{ x, y, z, ta, tb fp.Elt }
type pointR2 struct {
	pointR3
	z2 fp.Elt
}
type pointR3 struct{ addYX, subYX, dt2 fp.Elt }

func (P *pointR1) neg() {
	fp.Neg(&P.x, &P.x)
	fp.Neg(&P.ta, &P.ta)
}

func (P *pointR1) SetIdentity() {
	P.x = fp.Elt{}
	fp.SetOne(&P.y)
	fp.SetOne(&P.z)
	P.ta = fp.Elt{}
	P.tb = fp.Elt{}
}

func (P *pointR1) toAffine() {
	fp.Inv(&P.z, &P.z)
	fp.Mul(&P.x, &P.x, &P.z)
	fp.Mul(&P.y, &P.y, &P.z)
	fp.Modp(&P.x)
	fp.Modp(&P.y)
	fp.SetOne(&P.z)
	P.ta = P.x
	P.tb = P.y
}

func (P *pointR1) ToBytes(k []byte) {
	P.toAffine()
	var x [fp.Size]byte
	fp.ToBytes(k, &P.y)
	fp.ToBytes(x[:], &P.x)
	b := x[0] & 1
	k[Size-1] = k[Size-1] | (b << 7)
}

func (P *pointR1) FromBytes(k *[Size]byte) bool {
	signX := k[Size-1] >> 7
	copy(P.y[:], k[:])
	P.y[Size-1] &= 0x7F
	p := fp.P()
	if isLtModulus := isLessThan(P.y[:], p[:]); !isLtModulus {
		return false
	}

	one, u, v := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	fp.SetOne(one)
	fp.Sqr(u, &P.y)                        // u = y^2
	fp.Mul(v, u, (*fp.Elt)(&curve.paramD)) // v = dy^2
	fp.Sub(u, u, one)                      // u = y^2-1
	fp.Add(v, v, one)                      // v = dy^2+1
	isQR := fp.InvSqrt(&P.x, u, v)         // x = sqrt(u/v)
	if !isQR {
		return false
	}
	fp.Modp(&P.x) // x = x mod p
	if fp.IsZero(&P.x) && signX == 1 {
		return false
	}
	if signX != (P.x[0] & 1) {
		fp.Neg(&P.x, &P.x)
	}
	P.ta = P.x
	P.tb = P.y
	fp.SetOne(&P.z)
	return true
}

func (P *pointR1) double() {
	Px, Py, Pz, Pta, Ptb := &P.x, &P.y, &P.z, &P.ta, &P.tb
	a := Px
	b := Py
	c := Pz
	d := Pta
	e := Ptb
	f := b
	g := a
	fp.Add(e, Px, Py)
	fp.Sqr(a, Px)
	fp.Sqr(b, Py)
	fp.Sqr(c, Pz)
	fp.Add(c, c, c)
	fp.Add(d, a, b)
	fp.Sqr(e, e)
	fp.Sub(e, e, d)
	fp.Sub(f, b, a)
	fp.Sub(g, c, f)
	fp.Mul(Pz, f, g)
	fp.Mul(Px, e, g)
	fp.Mul(Py, d, f)
}

func (P *pointR1) mixAdd(Q *pointR3) {
	addYX := &Q.addYX
	subYX := &Q.subYX
	dt2 := &Q.dt2
	Px := &P.x
	Py := &P.y
	Pz := &P.z
	Pta := &P.ta
	Ptb := &P.tb
	a := Px
	b := Py
	c := &fp.Elt{}
	d := b
	e := Pta
	f := a
	g := b
	h := Ptb
	fp.Mul(c, Pta, Ptb)
	fp.Sub(h, b, a)
	fp.Add(b, b, a)
	fp.Mul(a, h, subYX)
	fp.Mul(b, b, addYX)
	fp.Sub(e, b, a)
	fp.Add(h, b, a)
	fp.Add(d, Pz, Pz)
	fp.Mul(c, c, dt2)
	fp.Sub(f, d, c)
	fp.Add(g, d, c)
	fp.Mul(Pz, f, g)
	fp.Mul(Px, e, f)
	fp.Mul(Py, g, h)
}

func (P *pointR1) add(Q *pointR2) {
	addYX := &Q.addYX
	subYX := &Q.subYX
	dt2 := &Q.dt2
	z2 := &Q.z2
	Px := &P.x
	Py := &P.y
	Pz := &P.z
	Pta := &P.ta
	Ptb := &P.tb
	a := Px
	b := Py
	c := &fp.Elt{}
	d := b
	e := Pta
	f := a
	g := b
	h := Ptb
	fp.Mul(c, Pta, Ptb)
	fp.Sub(h, b, a)
	fp.Add(b, b, a)
	fp.Mul(a, h, subYX)
	fp.Mul(b, b, addYX)
	fp.Sub(e, b, a)
	fp.Add(h, b, a)
	fp.Mul(d, Pz, z2)
	fp.Mul(c, c, dt2)
	fp.Sub(f, d, c)
	fp.Add(g, d, c)
	fp.Mul(Pz, f, g)
	fp.Mul(Px, e, f)
	fp.Mul(Py, g, h)
}

func (P *pointR1) oddMultiples(T []pointR2) {
	var R pointR2
	n := len(T)
	T[0].fromR1(P)
	_2P := *P
	_2P.double()
	R.fromR1(&_2P)
	for i := 1; i < n; i++ {
		P.add(&R)
		T[i].fromR1(P)
	}
}

func (P *pointR1) isEqual(Q *pointR1) bool {
	l, r := &fp.Elt{}, &fp.Elt{}
	fp.Mul(l, &P.x, &Q.z)
	fp.Mul(r, &Q.x, &P.z)
	fp.Sub(l, l, r)
	b := fp.IsZero(l)
	fp.Mul(l, &P.y, &Q.z)
	fp.Mul(r, &Q.y, &P.z)
	fp.Sub(l, l, r)
	b = b && fp.IsZero(l)
	fp.Mul(l, &P.ta, &P.tb)
	fp.Mul(l, l, &Q.z)
	fp.Mul(r, &Q.ta, &Q.tb)
	fp.Mul(r, r, &P.z)
	fp.Sub(l, l, r)
	b = b && fp.IsZero(l)
	return b
}

func (P *pointR3) neg() {
	P.addYX, P.subYX = P.subYX, P.addYX
	fp.Neg(&P.dt2, &P.dt2)
}

func (P *pointR2) fromR1(Q *pointR1) {
	fp.Add(&P.addYX, &Q.y, &Q.x)
	fp.Sub(&P.subYX, &Q.y, &Q.x)
	fp.Mul(&P.dt2, &Q.ta, &Q.tb)
	fp.Mul(&P.dt2, &P.dt2, (*fp.Elt)(&curve.paramD))
	fp.Add(&P.dt2, &P.dt2, &P.dt2)
	fp.Add(&P.z2, &Q.z, &Q.z)
}

func (P *pointR3) cneg(b int) {
	t := &fp.Elt{}
	fp.Cswap(&P.addYX, &P.subYX, uint(b))
	fp.Neg(t, &P.dt2)
	fp.Cmov(&P.dt2, t, uint(b))
}

func (P *pointR3) cmov(Q *pointR3, b int) {
	fp.Cmov(&P.addYX, &Q.addYX, uint(b))
	fp.Cmov(&P.subYX, &Q.subYX, uint(b))
	fp.Cmov(&P.dt2, &Q.dt2, uint(b))
}
