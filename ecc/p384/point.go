package p384

import (
	"fmt"
	"math/big"
)

// affinePoint represents an affine point of the curve. The point at
// infinity is (0,0) leveraging that it is not an affine point.
type affinePoint struct{ x, y fp384 }

func (ap affinePoint) String() string {
	return fmt.Sprintf("x: %v\ny: %v", ap.x, ap.y)
}

func newAffinePoint(X, Y *big.Int) *affinePoint {
	var P affinePoint
	P.x.SetBigInt(X)
	P.y.SetBigInt(Y)
	montEncode(&P.x, &P.x)
	montEncode(&P.y, &P.y)
	return &P
}

func (ap *affinePoint) neg() { fp384Neg(&ap.y, &ap.y) }

func (ap *affinePoint) toJacobian() *jacobianPoint {
	var P jacobianPoint
	if !ap.isZero() {
		P.x = ap.x
		P.y = ap.y
		montEncode(&P.z, &fp384{1})
	}
	return &P
}

func (ap *affinePoint) toInt() (*big.Int, *big.Int) {
	x, y := &fp384{}, &fp384{}
	montDecode(x, &ap.x)
	montDecode(y, &ap.y)
	return x.BigInt(), y.BigInt()
}

func (ap *affinePoint) isZero() bool {
	zero := fp384{}
	return ap.x == zero && ap.y == zero
}

// OddMultiples calculates the points iP for i={1,3,5,7,..., 2^(n-1)-1}
// Ensure that n > 1, otherwise it returns nil.
func (ap affinePoint) oddMultiples(n uint) []jacobianPoint {
	P := ap.toJacobian()
	var t []jacobianPoint = nil
	if n > 1 {
		s := 1 << (n - 1)
		t = make([]jacobianPoint, s)
		t[0] = *P
		_2P := *P
		_2P.double()
		for i := 1; i < s; i++ {
			t[i].add(&t[i-1], &_2P)
		}
	}
	return t
}

// jacobianPoint represents a point in Jacobian coordinates. The point at
// infinity is any point with z=0 including (0,0,0) (although this is not a
// projective point).
type jacobianPoint struct{ x, y, z fp384 }

func (P *jacobianPoint) neg() { fp384Neg(&P.y, &P.y) }

// condNeg if P is negated if b=1.
func (P *jacobianPoint) cneg(b int) {
	var mY fp384
	fp384Neg(&mY, &P.y)
	fp384Cmov(&P.y, &mY, b)
}

// cmov sets P to Q if b=1
func (P *jacobianPoint) cmov(Q *jacobianPoint, b int) {
	fp384Cmov(&P.x, &Q.x, b)
	fp384Cmov(&P.y, &Q.y, b)
	fp384Cmov(&P.z, &Q.z, b)
}

func (P *jacobianPoint) toAffine() *affinePoint {
	var aP affinePoint
	z, z2 := &fp384{}, &fp384{}
	fp384Inv(z, &P.z)
	fp384Sqr(z2, z)
	fp384Mul(&aP.x, &P.x, z2)
	fp384Mul(&aP.y, &P.y, z)
	fp384Mul(&aP.y, &aP.y, z2)
	return &aP
}

func (P *jacobianPoint) toInt() (*big.Int, *big.Int, *big.Int) {
	x, y, z := &fp384{}, &fp384{}, &fp384{}
	montDecode(x, &P.x)
	montDecode(y, &P.y)
	montDecode(z, &P.z)
	return x.BigInt(), y.BigInt(), z.BigInt()
}

func (P *jacobianPoint) isZero() bool { return P.z == fp384{} }

// add calculates P=Q+R such that Q and R are different than the identity point,
// and Q!==R. This function cannot be used for doublings.
func (P *jacobianPoint) add(Q, R *jacobianPoint) {
	if Q.isZero() {
		*P = *R
		return
	} else if R.isZero() {
		*P = *Q
		return
	}

	// Cohen-Miyagi-Ono (1998)
	// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2
	X1, Y1, Z1 := &Q.x, &Q.y, &Q.z
	X2, Y2, Z2 := &R.x, &R.y, &R.z
	Z1Z1, Z2Z2, U1, U2 := &fp384{}, &fp384{}, &fp384{}, &fp384{}
	H, HH, HHH, RR := &fp384{}, &fp384{}, &fp384{}, &fp384{}
	V, t4, t5, t6, t7, t8 := &fp384{}, &fp384{}, &fp384{}, &fp384{}, &fp384{}, &fp384{}
	t0, t1, t2, t3, S1, S2 := &fp384{}, &fp384{}, &fp384{}, &fp384{}, &fp384{}, &fp384{}
	fp384Sqr(Z1Z1, Z1)     // Z1Z1 = Z1 ^ 2
	fp384Sqr(Z2Z2, Z2)     // Z2Z2 = Z2 ^ 2
	fp384Mul(U1, X1, Z2Z2) // U1 = X1 * Z2Z2
	fp384Mul(U2, X2, Z1Z1) // U2 = X2 * Z1Z1
	fp384Mul(t0, Z2, Z2Z2) // t0 = Z2 * Z2Z2
	fp384Mul(S1, Y1, t0)   // S1 = Y1 * t0
	fp384Mul(t1, Z1, Z1Z1) // t1 = Z1 * Z1Z1
	fp384Mul(S2, Y2, t1)   // S2 = Y2 * t1
	fp384Sub(H, U2, U1)    // H = U2 - U1
	fp384Sqr(HH, H)        // HH = H ^ 2
	fp384Mul(HHH, H, HH)   // HHH = H * HH
	fp384Sub(RR, S2, S1)   // r = S2 - S1
	fp384Mul(V, U1, HH)    // V = U1 * HH
	fp384Sqr(t2, RR)       // t2 = r ^ 2
	fp384Add(t3, V, V)     // t3 = V + V
	fp384Sub(t4, t2, HHH)  // t4 = t2 - HHH
	fp384Sub(&P.x, t4, t3) // X3 = t4 - t3
	fp384Sub(t5, V, &P.x)  // t5 = V - X3
	fp384Mul(t6, S1, HHH)  // t6 = S1 * HHH
	fp384Mul(t7, RR, t5)   // t7 = r * t5
	fp384Sub(&P.y, t7, t6) // Y3 = t7 - t6
	fp384Mul(t8, Z2, H)    // t8 = Z2 * H
	fp384Mul(&P.z, Z1, t8) // Z3 = Z1 * t8
}

// mixadd calculates P=Q+R such that P and Q different than the identity point,
// and Q not in {P,-P, O}.
func (P *jacobianPoint) mixadd(Q *jacobianPoint, R *affinePoint) {
	if Q.isZero() {
		*P = *R.toJacobian()
		return
	} else if R.isZero() {
		*P = *Q
		return
	}

	z1z1, u2 := &fp384{}, &fp384{}
	fp384Sqr(z1z1, &Q.z)
	fp384Mul(u2, &R.x, z1z1)

	s2 := &fp384{}
	fp384Mul(s2, &R.y, &Q.z)
	fp384Mul(s2, s2, z1z1)
	if Q.x == *u2 {
		if Q.y != *s2 {
			*P = jacobianPoint{}
			return
		}
		*P = *Q
		P.double()
		return
	}

	h, r := &fp384{}, &fp384{}
	fp384Sub(h, u2, &Q.x)
	fp384Mul(&P.z, h, &Q.z)
	fp384Sub(r, s2, &Q.y)

	h2, h3 := &fp384{}, &fp384{}
	fp384Sqr(h2, h)
	fp384Mul(h3, h2, h)
	h3y1 := &fp384{}
	fp384Mul(h3y1, h3, &Q.y)

	h2x1 := &fp384{}
	fp384Mul(h2x1, h2, &Q.x)

	fp384Sqr(&P.x, r)
	fp384Sub(&P.x, &P.x, h3)
	fp384Sub(&P.x, &P.x, h2x1)
	fp384Sub(&P.x, &P.x, h2x1)

	fp384Sub(&P.y, h2x1, &P.x)
	fp384Mul(&P.y, &P.y, r)
	fp384Sub(&P.y, &P.y, h3y1)
}

func (P *jacobianPoint) double() {
	delta, gamma, alpha, alpha2 := &fp384{}, &fp384{}, &fp384{}, &fp384{}
	fp384Sqr(delta, &P.z)
	fp384Sqr(gamma, &P.y)
	fp384Sub(alpha, &P.x, delta)
	fp384Add(alpha2, &P.x, delta)
	fp384Mul(alpha, alpha, alpha2)
	*alpha2 = *alpha
	fp384Add(alpha, alpha, alpha)
	fp384Add(alpha, alpha, alpha2)

	beta := &fp384{}
	fp384Mul(beta, &P.x, gamma)

	beta8 := &fp384{}
	fp384Sqr(&P.x, alpha)
	fp384Add(beta8, beta, beta)
	fp384Add(beta8, beta8, beta8)
	fp384Add(beta8, beta8, beta8)
	fp384Sub(&P.x, &P.x, beta8)

	fp384Add(&P.z, &P.y, &P.z)
	fp384Sqr(&P.z, &P.z)
	fp384Sub(&P.z, &P.z, gamma)
	fp384Sub(&P.z, &P.z, delta)

	fp384Add(beta, beta, beta)
	fp384Add(beta, beta, beta)
	fp384Sub(beta, beta, &P.x)

	fp384Mul(&P.y, alpha, beta)

	fp384Sqr(gamma, gamma)
	fp384Add(gamma, gamma, gamma)
	fp384Add(gamma, gamma, gamma)
	fp384Add(gamma, gamma, gamma)
	fp384Sub(&P.y, &P.y, gamma)
}

func (P jacobianPoint) String() string {
	return fmt.Sprintf("x: %v\ny: %v\nz: %v", P.x, P.y, P.z)
}
