package bls12381

import (
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381/ff"
)

func checkE(t *testing.T, x *ff.Fp12, y *ff.Fp12) {
	four := &ff.Fp12{}
	four[0][0][0].SetUint64(4)

	xcube := &ff.Fp12{}
	xcube.Mul(x, x)
	xcube.Mul(xcube, x)

	ysq := &ff.Fp12{}
	ysq.Mul(y, y)

	check := &ff.Fp12{}
	check.Add(xcube, four)
	if check.IsEqual(ysq) != 1 {
		t.Log("failure of isogeny to E to verify")
		t.Fail()
	}
}

func checkEprime(t *testing.T, x *ff.Fp12, y *ff.Fp12) {
	four := &ff.Fp12{}
	four[0][0][0].SetUint64(4)
	ysq := &ff.Fp12{}
	xcube := &ff.Fp12{}
	uplusOne := &ff.Fp12{}
	uplusOne[0][0][1].SetOne()
	uplusOne[0][0][0].SetOne()

	b := &ff.Fp12{}
	b.Mul(uplusOne, four)

	check := &ff.Fp12{}
	ysq.Mul(y, y)

	xcube.Mul(x, x)
	xcube.Mul(x, xcube)
	check.Add(xcube, b)
	if check.IsEqual(ysq) != 1 {
		t.Log("failure to return to original curve")
		t.Fail()
	}
}

func TestPsi(t *testing.T) {
	xp12 := &ff.Fp12{}
	yp12 := &ff.Fp12{}
	Q := &G2{}
	P := randomG2(t)
	*Q = *P
	P.toAffine()
	Q.psi()
	Q.toAffine()
	w := &ff.Fp12{}
	w[1].SetOne()
	wsq := &ff.Fp12{}
	wsq.Sqr(w)
	wcube := &ff.Fp12{}
	wcube.Mul(wsq, w)
	wsqInv := &ff.Fp12{}
	wsqInv.Inv(wsq)
	wcubInv := &ff.Fp12{}
	wcubInv.Inv(wcube)

	uplusOne := &ff.Fp12{}
	uplusOne[0][0][1].SetOne()
	uplusOne[0][0][0].SetOne()
	wsix := &ff.Fp12{}
	wsix.Mul(wcube, wcube)
	if wsix.IsEqual(uplusOne) != 1 {
		t.Log("w^6 is not u+1")
		t.Fail()
	}

	xp12[0][0] = P.x
	yp12[0][0] = P.y
	// E' is yp^2=xp^3+4(u+1)
	t.Log("testing input")
	checkEprime(t, xp12, yp12)
	// let x12 = xp/w^2
	// let y12 = yp/w^3
	// Then y12^2=x12^3+4

	x12 := &ff.Fp12{}
	y12 := &ff.Fp12{}

	x12.Mul(xp12, wsqInv)
	y12.Mul(yp12, wcubInv)
	t.Log("testing intermediate")
	checkE(t, x12, y12)
	// Do Frobenius
	x12.Frob(x12)
	y12.Frob(y12)
	t.Log("testing post frobenius")
	checkE(t, x12, y12)
	// And return to original
	x12.Mul(x12, wsq)
	y12.Mul(y12, wcube)

	// Now we should have y^2=x^3+4(u+1)
	checkEprime(t, x12, y12)
	qx12 := &ff.Fp12{}
	qx12[0][0] = Q.x
	qy12 := &ff.Fp12{}
	qy12[0][0] = Q.y
	if x12.IsEqual(qx12) != 1 {
		t.Log("failure in evaluation of x")
		t.Fail()
	}
	if y12.IsEqual(qy12) != 1 {
		t.Log("failure in evaluation of y")
		t.Fail()
	}
}
