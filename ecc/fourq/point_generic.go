//go:build !amd64 || purego
// +build !amd64 purego

package fourq

func doubleGeneric(P *pointR1) {
	Px := &P.X
	Py := &P.Y
	Pz := &P.Z
	Pta := &P.Ta
	Ptb := &P.Tb
	a := Px
	b := Py
	c := Pz
	d := Pta
	e := Ptb
	f := b
	g := a
	fqAdd(e, Px, Py)
	fqSqr(a, Px)
	fqSqr(b, Py)
	fqSqr(c, Pz)
	fqAdd(c, c, c)
	fqAdd(d, a, b)
	fqSqr(e, e)
	fqSub(e, e, d)
	fqSub(f, b, a)
	fqSub(g, c, f)
	fqMul(Pz, f, g)
	fqMul(Px, e, g)
	fqMul(Py, d, f)
}

func addGeneric(P *pointR1, Q *pointR2) {
	addYX := &Q.addYX
	subYX := &Q.subYX
	z2 := &Q.z2
	dt2 := &Q.dt2
	Px := &P.X
	Py := &P.Y
	Pz := &P.Z
	Pta := &P.Ta
	Ptb := &P.Tb
	a := Px
	b := Py
	c := &Fq{}
	d := b
	e := Pta
	f := a
	g := b
	h := Ptb
	fqMul(c, Pta, Ptb)
	fqSub(h, b, a)
	fqAdd(b, b, a)
	fqMul(a, h, subYX)
	fqMul(b, b, addYX)
	fqSub(e, b, a)
	fqAdd(h, b, a)
	fqMul(d, Pz, z2)
	fqMul(c, c, dt2)
	fqSub(f, d, c)
	fqAdd(g, d, c)
	fqMul(Pz, f, g)
	fqMul(Px, e, f)
	fqMul(Py, g, h)
}

func mixAddGeneric(P *pointR1, Q *pointR3) {
	addYX := &Q.addYX
	subYX := &Q.subYX
	dt2 := &Q.dt2
	Px := &P.X
	Py := &P.Y
	Pz := &P.Z
	Pta := &P.Ta
	Ptb := &P.Tb
	a := Px
	b := Py
	c := &Fq{}
	d := b
	e := Pta
	f := a
	g := b
	h := Ptb
	fqMul(c, Pta, Ptb)
	fqSub(h, b, a)
	fqAdd(b, b, a)
	fqMul(a, h, subYX)
	fqMul(b, b, addYX)
	fqSub(e, b, a)
	fqAdd(h, b, a)
	fqAdd(d, Pz, Pz)
	fqMul(c, c, dt2)
	fqSub(f, d, c)
	fqAdd(g, d, c)
	fqMul(Pz, f, g)
	fqMul(Px, e, f)
	fqMul(Py, g, h)
}
