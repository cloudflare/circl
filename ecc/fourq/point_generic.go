// +build !amd64 purego

package fourq

func doubleGeneric(P *pointR1) {
	var Px = &P.X
	var Py = &P.Y
	var Pz = &P.Z
	var Pta = &P.Ta
	var Ptb = &P.Tb
	var a = Px
	var b = Py
	var c = Pz
	var d = Pta
	var e = Ptb
	var f = b
	var g = a
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
	var addYX = &Q.addYX
	var subYX = &Q.subYX
	var z2 = &Q.z2
	var dt2 = &Q.dt2
	var Px = &P.X
	var Py = &P.Y
	var Pz = &P.Z
	var Pta = &P.Ta
	var Ptb = &P.Tb
	var a = Px
	var b = Py
	var c = &Fq{}
	var d = b
	var e = Pta
	var f = a
	var g = b
	var h = Ptb
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
	var addYX = &Q.addYX
	var subYX = &Q.subYX
	var dt2 = &Q.dt2
	var Px = &P.X
	var Py = &P.Y
	var Pz = &P.Z
	var Pta = &P.Ta
	var Ptb = &P.Tb
	var a = Px
	var b = Py
	var c = &Fq{}
	var d = b
	var e = Pta
	var f = a
	var g = b
	var h = Ptb
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
