package ed25519

import fp255 "github.com/cloudflare/circl/math/fp25519"

type pointR1 struct{ x, y, z, ta, tb fp255.Elt }
type pointR2 struct {
	pointR3
	z2 fp255.Elt
}
type pointR3 struct{ addYX, subYX, dt2 fp255.Elt }

func (P *pointR1) neg() {
	fp255.Neg(&P.x, &P.x)
	fp255.Neg(&P.ta, &P.ta)
}

func (P *pointR1) SetIdentity() {
	P.x = fp255.Elt{}
	fp255.SetOne(&P.y)
	fp255.SetOne(&P.z)
	P.ta = fp255.Elt{}
	P.tb = fp255.Elt{}
}

func (P *pointR1) toAffine() {
	fp255.Inv(&P.z, &P.z)
	fp255.Mul(&P.x, &P.x, &P.z)
	fp255.Mul(&P.y, &P.y, &P.z)
	fp255.Modp(&P.x)
	fp255.Modp(&P.y)
	fp255.SetOne(&P.z)
	P.ta = P.x
	P.tb = P.y
}

func (P *pointR1) ToBytes(k []byte) {
	P.toAffine()
	var x [fp255.Size]byte
	fp255.ToBytes(k, &P.y)
	fp255.ToBytes(x[:], &P.x)
	b := x[0] & 1
	k[Size-1] = k[Size-1] | (b << 7)
}

func (P *pointR1) FromBytes(k *[Size]byte) bool {
	signX := k[Size-1] >> 7
	copy(P.y[:], k[:])
	P.y[Size-1] &= 0x7F
	p := fp255.P()
	if isLtModulus := isLessThan(P.y[:], p[:]); !isLtModulus {
		return false
	}

	one, u, v := &fp255.Elt{}, &fp255.Elt{}, &fp255.Elt{}
	fp255.SetOne(one)
	fp255.Sqr(u, &P.y)                           // u = y^2
	fp255.Mul(v, u, (*fp255.Elt)(&curve.paramD)) // v = dy^2
	fp255.Sub(u, u, one)                         // u = y^2-1
	fp255.Add(v, v, one)                         // v = dy^2+1
	isQR := fp255.InvSqrt(&P.x, u, v)            // x = sqrt(u/v)
	if !isQR {
		return false
	}
	fp255.Modp(&P.x) // x = x mod p
	if fp255.IsZero(&P.x) && signX == 1 {
		return false
	}
	if signX != (P.x[0] & 1) {
		fp255.Neg(&P.x, &P.x)
	}
	P.ta = P.x
	P.tb = P.y
	fp255.SetOne(&P.z)
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
	fp255.Add(e, Px, Py)
	fp255.Sqr(a, Px)
	fp255.Sqr(b, Py)
	fp255.Sqr(c, Pz)
	fp255.Add(c, c, c)
	fp255.Add(d, a, b)
	fp255.Sqr(e, e)
	fp255.Sub(e, e, d)
	fp255.Sub(f, b, a)
	fp255.Sub(g, c, f)
	fp255.Mul(Pz, f, g)
	fp255.Mul(Px, e, g)
	fp255.Mul(Py, d, f)
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
	c := &fp255.Elt{}
	d := b
	e := Pta
	f := a
	g := b
	h := Ptb
	fp255.Mul(c, Pta, Ptb)
	fp255.Sub(h, b, a)
	fp255.Add(b, b, a)
	fp255.Mul(a, h, subYX)
	fp255.Mul(b, b, addYX)
	fp255.Sub(e, b, a)
	fp255.Add(h, b, a)
	fp255.Add(d, Pz, Pz)
	fp255.Mul(c, c, dt2)
	fp255.Sub(f, d, c)
	fp255.Add(g, d, c)
	fp255.Mul(Pz, f, g)
	fp255.Mul(Px, e, f)
	fp255.Mul(Py, g, h)
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
	c := &fp255.Elt{}
	d := b
	e := Pta
	f := a
	g := b
	h := Ptb
	fp255.Mul(c, Pta, Ptb)
	fp255.Sub(h, b, a)
	fp255.Add(b, b, a)
	fp255.Mul(a, h, subYX)
	fp255.Mul(b, b, addYX)
	fp255.Sub(e, b, a)
	fp255.Add(h, b, a)
	fp255.Mul(d, Pz, z2)
	fp255.Mul(c, c, dt2)
	fp255.Sub(f, d, c)
	fp255.Add(g, d, c)
	fp255.Mul(Pz, f, g)
	fp255.Mul(Px, e, f)
	fp255.Mul(Py, g, h)
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
	l, r := &fp255.Elt{}, &fp255.Elt{}
	fp255.Mul(l, &P.x, &Q.z)
	fp255.Mul(r, &Q.x, &P.z)
	fp255.Sub(l, l, r)
	b := fp255.IsZero(l)
	fp255.Mul(l, &P.y, &Q.z)
	fp255.Mul(r, &Q.y, &P.z)
	fp255.Sub(l, l, r)
	b = b && fp255.IsZero(l)
	fp255.Mul(l, &P.ta, &P.tb)
	fp255.Mul(l, l, &Q.z)
	fp255.Mul(r, &Q.ta, &Q.tb)
	fp255.Mul(r, r, &P.z)
	fp255.Sub(l, l, r)
	b = b && fp255.IsZero(l)
	return b
}

func (P *pointR3) neg() {
	P.addYX, P.subYX = P.subYX, P.addYX
	fp255.Neg(&P.dt2, &P.dt2)
}

func (P *pointR2) fromR1(Q *pointR1) {
	fp255.Add(&P.addYX, &Q.y, &Q.x)
	fp255.Sub(&P.subYX, &Q.y, &Q.x)
	fp255.Mul(&P.dt2, &Q.ta, &Q.tb)
	fp255.Mul(&P.dt2, &P.dt2, (*fp255.Elt)(&curve.paramD))
	fp255.Add(&P.dt2, &P.dt2, &P.dt2)
	fp255.Add(&P.z2, &Q.z, &Q.z)
}

func (P *pointR3) cneg(b int) {
	t := &fp255.Elt{}
	fp255.Cswap(&P.addYX, &P.subYX, uint(b))
	fp255.Neg(t, &P.dt2)
	fp255.Cmov(&P.dt2, t, uint(b))
}

func (P *pointR3) cmov(Q *pointR3, b int) {
	fp255.Cmov(&P.addYX, &Q.addYX, uint(b))
	fp255.Cmov(&P.subYX, &Q.subYX, uint(b))
	fp255.Cmov(&P.dt2, &Q.dt2, uint(b))
}
