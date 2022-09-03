package fourq

import (
	"crypto/subtle"
	"encoding/binary"
	"math/bits"
)

type pointR1 struct {
	X, Y, Z, Ta, Tb Fq // (x,y,z,t=ta*tb)
}

type pointR3 struct {
	addYX Fq // y + x
	subYX Fq // y - x
	dt2   Fq // 2*d*t
}

type pointR2 struct {
	pointR3
	z2 Fq // 2 * z
}

// subYDiv16 update x = (x - y) / 16.
func subYDiv16(x *[5]uint64, y int64) {
	s := uint64(y >> 63)
	x0, b0 := bits.Sub64((*x)[0], uint64(y), 0)
	x1, b1 := bits.Sub64((*x)[1], s, b0)
	x2, b2 := bits.Sub64((*x)[2], s, b1)
	x3, b3 := bits.Sub64((*x)[3], s, b2)
	x4, _ := bits.Sub64((*x)[4], s, b3)
	(*x)[0] = (x0 >> 4) | (x1 << 60)
	(*x)[1] = (x1 >> 4) | (x2 << 60)
	(*x)[2] = (x2 >> 4) | (x3 << 60)
	(*x)[3] = (x3 >> 4) | (x4 << 60)
	(*x)[4] = (x4 >> 4)
}

// condAddOrderN updates x = x+order if x is even, otherwise x remains unchanged.
func condAddOrderN(x *[5]uint64) {
	var o [4]uint64
	isOdd := (x[0] & 0x1) - 1
	for i := range orderGenerator {
		o[i] = isOdd & orderGenerator[i]
	}
	x0, c0 := bits.Add64((*x)[0], o[0], 0)
	x1, c1 := bits.Add64((*x)[1], o[1], c0)
	x2, c2 := bits.Add64((*x)[2], o[2], c1)
	x3, c3 := bits.Add64((*x)[3], o[3], c2)
	x4, _ := bits.Add64((*x)[4], 0, c3)
	(*x)[0] = x0
	(*x)[1] = x1
	(*x)[2] = x2
	(*x)[3] = x3
	(*x)[4] = x4
}

func recodeScalar(d *[65]int8, k *[32]byte) {
	var m [5]uint64
	m[0] = binary.LittleEndian.Uint64(k[0:8])
	m[1] = binary.LittleEndian.Uint64(k[8:16])
	m[2] = binary.LittleEndian.Uint64(k[16:24])
	m[3] = binary.LittleEndian.Uint64(k[24:32])
	condAddOrderN(&m)
	for i := 0; i < 64; i++ {
		d[i] = int8((m[0] & 0x1f) - 16)
		subYDiv16(&m, int64(d[i]))
	}
	d[64] = int8(m[0])
}

func (P *pointR1) oddMultiples(T *[8]pointR2) {
	var _2P, R pointR1
	var _p2P pointR2
	_2P.copy(P)
	_2P.double()
	_p2P.FromR1(&_2P)
	R.copy(P)
	T[0].FromR1(P)
	for i := 1; i < 8; i++ {
		R.add(&_p2P)
		T[i].FromR1(&R)
	}
}

// scalarMult calculates P = k*Q.
func (P *pointR1) ScalarMult(k *[32]byte, Q *pointR1) {
	var TabQ [8]pointR2
	var S pointR2
	var d [65]int8
	Q.oddMultiples(&TabQ)
	recodeScalar(&d, k)
	P.SetIdentity()
	for i := 64; i >= 0; i-- {
		P.double()
		P.double()
		P.double()
		P.double()
		mask := d[i] >> 7
		absDi := (d[i] + mask) ^ mask
		inx := int((absDi - 1) >> 1)
		sig := int((d[i] >> 7) & 0x1)
		for j := range TabQ {
			S.cmov(&TabQ[j], int((uint64(uint32(inx^j))-1)>>63))
		}
		S.cneg(sig)
		P.add(&S)
	}
}

// absolute returns always a positive value.
func absolute(x int32) int32 {
	mask := x >> 31
	return (x + mask) ^ mask
}

// div2subY update x = (x/2) - y.
func div2subY(x *[5]uint64, y int64) {
	s := uint64(y >> 63)
	x0 := (*x)[0]
	x1 := (*x)[1]
	x2 := (*x)[2]
	x3 := (*x)[3]
	x0 = (x0 >> 1) | (x1 << 63)
	x1 = (x1 >> 1) | (x2 << 63)
	x2 = (x2 >> 1) | (x3 << 63)
	x3 = (x3 >> 1)

	x0, b0 := bits.Sub64(x0, uint64(y), 0)
	x1, b1 := bits.Sub64(x1, s, b0)
	x2, b2 := bits.Sub64(x2, s, b1)
	x3, _ = bits.Sub64(x3, s, b2)
	(*x)[0] = x0
	(*x)[1] = x1
	(*x)[2] = x2
	(*x)[3] = x3
}

// mLSBRecoding is the odd-only modified LSB-set.
//
// Reference:
//
//	"Efficient and secure algorithms for GLV-based scalar multiplication and
//	 their implementation on GLV–GLS curves" by (Faz-Hernandez et al.)
//	 http://doi.org/10.1007/s13389-014-0085-7.
func mLSBRecoding(L []int8, k []byte) {
	const e = (fxT + fxW*fxV - 1) / (fxW * fxV)
	const d = e * fxV
	const l = d * fxW
	if len(L) == (l + 1) {
		var m [5]uint64
		m[0] = binary.LittleEndian.Uint64(k[0:8])
		m[1] = binary.LittleEndian.Uint64(k[8:16])
		m[2] = binary.LittleEndian.Uint64(k[16:24])
		m[3] = binary.LittleEndian.Uint64(k[24:32])
		condAddOrderN(&m)

		L[d-1] = 1
		for i := 0; i < d-1; i++ {
			kip1 := (m[(i+1)/64] >> (uint(i+1) % 64)) & 0x1
			L[i] = int8(kip1<<1) - 1
		}
		{ // right-shift by d
			const right = (d % 64)
			const left = 64 - (d % 64)
			const lim = (5*64 - d) / 64
			const j = d / 64
			for i := 0; i < lim; i++ {
				m[i] = (m[i+j] >> right) | (m[i+j+1] << left)
			}
			m[lim] = m[lim+j] >> right
		}
		for i := d; i < l; i++ {
			L[i] = L[i%d] * int8(m[0]&0x1)
			div2subY(&m, int64(L[i]>>1))
		}
		L[l] = int8(m[0])
	}
}

func (P *pointR1) ScalarBaseMult(scalar *[Size]byte) {
	var S pointR3
	const e = (fxT + fxW*fxV - 1) / (fxW * fxV)
	const d = e * fxV
	const l = d * fxW

	var L [l + 1]int8
	mLSBRecoding(L[:], scalar[:])
	P.SetIdentity()
	for ii := e - 1; ii >= 0; ii-- {
		P.double()
		for j := 0; j < fxV; j++ {
			dig := L[fxW*d-j*e+ii-e]
			for i := (fxW-1)*d - j*e + ii - e; i >= (2*d - j*e + ii - e); i = i - d {
				dig = 2*dig + L[i]
			}
			idx := absolute(int32(dig))
			sig := L[d-j*e+ii-e]
			Tabj := &tableBaseFixed[fxV-j-1]
			for k := 0; k < fx2w1; k++ {
				S.cmov(&Tabj[k], subtle.ConstantTimeEq(int32(k), idx))
			}
			S.cneg(subtle.ConstantTimeEq(int32(sig), -1))
			P.mixAdd(&S)
		}
	}
}

func (P *pointR1) copy(Q *pointR1) {
	fqCopy(&P.X, &Q.X)
	fqCopy(&P.Y, &Q.Y)
	fqCopy(&P.Ta, &Q.Ta)
	fqCopy(&P.Tb, &Q.Tb)
	fqCopy(&P.Z, &Q.Z)
}

func (P *pointR1) SetIdentity() {
	P.X.setZero()
	P.Y.setOne()
	P.Ta.setZero()
	P.Tb.setZero()
	P.Z.setOne()
}

func (P *pointR1) IsIdentity() bool {
	t0, t1 := &Fq{}, &Fq{}
	fqMul(t0, &P.Ta, &P.Tb)
	fqSub(t1, &P.Y, &P.Z)
	return P.X.isZero() && t0.isZero() && t1.isZero()
}

func (P *pointR1) ToAffine() {
	fqInv(&P.Z, &P.Z)
	fqMul(&P.X, &P.X, &P.Z)
	fqMul(&P.Y, &P.Y, &P.Z)
	fqMul(&P.Ta, &P.X, &P.Y)
	P.Tb.setOne()
	P.Z.setOne()
}

// Marshal encodes a point P into out buffer.
func (P *Point) Marshal(out *[Size]byte) {
	P.Y.toBytes(out[:])
	// b=0 if x is positive or zero
	// b=1 if x is negative
	b := (1 - fqSgn(&P.X)) >> 1
	out[Size-1] |= byte(b) << 7
}

// Unmarshal retrieves a point P from the input buffer. On success, returns true.
func (P *Point) Unmarshal(in *[Size]byte) bool {
	s := in[Size-1] >> 7
	in[Size-1] &= 0x7F
	if ok := P.Y.fromBytes(in[:]); !ok {
		return ok
	}
	in[Size-1] |= s << 7

	t0, t1, one := &Fq{}, &Fq{}, &Fq{}
	one.setOne()
	fqSqr(t0, &P.Y)                  // t0 = y^2
	fqMul(t1, t0, &paramD)           // t1 = d*y^2
	fqSub(t0, t0, one)               // t0 = y^2 - 1
	fqAdd(t1, t1, one)               // t1 = d*y^2 + 1
	fqSqrt(&P.X, t0, t1, 1-2*int(s)) // x = sqrt(t0/t1)

	if !P.IsOnCurve() {
		fpNeg(&P.X[1], &P.X[1])
	}
	return true
}

func (P *pointR1) IsOnCurve() bool {
	t0, lhs, rhs := &Fq{}, &Fq{}, &Fq{}

	fqAdd(t0, &P.Y, &P.X)    // t0  = y + x
	fqSub(lhs, &P.Y, &P.X)   // lhs = y - x
	fqMul(lhs, lhs, t0)      // lhs = y^2 - x^2
	fqMul(rhs, &P.X, &P.Y)   // rhs = xy
	fqSqr(rhs, rhs)          // rhs = x^2y^2
	fqMul(rhs, rhs, &paramD) // rhs = dx^2y^2
	t0.setOne()              // t0  = 1
	fqAdd(rhs, rhs, t0)      // rhs = 1 + dx^2y^2
	fqSub(t0, lhs, rhs)      // t0 = -x^2 + y^2 - (1 + dx^2y^2)
	return t0.isZero()
}

func (P *pointR1) isEqual(Q *pointR1) bool {
	l, r := &Fq{}, &Fq{}
	fqMul(l, &P.X, &Q.Z)
	fqMul(r, &Q.X, &P.Z)
	fqSub(l, l, r)
	b := l.isZero()
	fqMul(l, &P.Y, &Q.Z)
	fqMul(r, &Q.Y, &P.Z)
	fqSub(l, l, r)
	b = b && l.isZero()
	fqMul(l, &P.Ta, &P.Tb)
	fqMul(l, l, &Q.Z)
	fqMul(r, &Q.Ta, &Q.Tb)
	fqMul(r, r, &P.Z)
	fqSub(l, l, r)
	b = b && l.isZero()
	return b
}

func (P *pointR1) ClearCofactor() {
	var Q pointR2
	Q.FromR1(P)
	P.double()
	P.add(&Q)
	P.double()
	P.double()
	P.double()
	P.double()
	P.add(&Q)
	P.double()
	P.double()
	P.double()
}

func (P *pointR2) FromR1(Q *pointR1) {
	fqAdd(&P.addYX, &Q.Y, &Q.X)
	fqSub(&P.subYX, &Q.Y, &Q.X)
	fqAdd(&P.z2, &Q.Z, &Q.Z)
	fqMul(&P.dt2, &Q.Ta, &Q.Tb)
	fqMul(&P.dt2, &P.dt2, &paramD)
	fqAdd(&P.dt2, &P.dt2, &P.dt2)
}

func (P *pointR2) cmov(Q *pointR2, b int) {
	P.pointR3.cmov(&Q.pointR3, b)
	fqCmov(&P.z2, &Q.z2, b)
}

func (P *pointR3) cneg(b int) {
	var t Fq
	fqCopy(&t, &P.addYX)
	fqCmov(&P.addYX, &P.subYX, b)
	fqCmov(&P.subYX, &t, b)
	fqNeg(&t, &P.dt2)
	fqCmov(&P.dt2, &t, b)
}

func (P *pointR3) cmov(Q *pointR3, b int) {
	fqCmov(&P.addYX, &Q.addYX, b)
	fqCmov(&P.subYX, &Q.subYX, b)
	fqCmov(&P.dt2, &Q.dt2, b)
}
