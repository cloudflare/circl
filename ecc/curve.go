// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package ecc

import (
	"crypto/elliptic"
	"encoding/asn1"
	"math/big"
)

// initial binary curve implementation reference:
// https://github.com/RyuaNerin/elliptic2
// https://neuromancer.sk/std/

type Curve interface {
	elliptic.Curve
	Oid() asn1.ObjectIdentifier
}

type BinaryCurve interface {
	Curve
	BinaryParams() *BinaryCurveParams
}

// ensure curve implements the elliptic.Curve interface
var (
	_ elliptic.Curve = (*CurveParams)(nil)
	_ elliptic.Curve = (*BinaryCurveParams)(nil)
)

type CurveParams struct {
	elliptic.Curve
	OidVal asn1.ObjectIdentifier
}

type BinaryCurveParams struct {
	Name    string
	BitSize int
	F       *big.Int // field
	A, B    *big.Int // params
	Gx, Gy  *big.Int // generator
	N       *big.Int // order
	H       int      // cofactor
	OidVal  asn1.ObjectIdentifier
}

func (c *CurveParams) Oid() asn1.ObjectIdentifier {
	return c.OidVal
}

func (b *BinaryCurveParams) Oid() asn1.ObjectIdentifier {
	return b.OidVal
}

func (b *BinaryCurveParams) Params() *elliptic.CurveParams {
	return &elliptic.CurveParams{
		P:       b.F,
		N:       b.N,
		B:       b.B,
		Gx:      b.Gx,
		Gy:      b.Gy,
		BitSize: b.BitSize,
		Name:    b.Name,
	}
}

func (b *BinaryCurveParams) BinaryParams() *BinaryCurveParams {
	return b
}

func (b *BinaryCurveParams) IsOnCurve(x_, y_ *big.Int) bool {
	// https://gist.github.com/kurtbrose/4423605#file-elliptic-py-L158-L160

	// yy + xy = xxx + axx + b
	x := wrapBFI(x_)
	y := wrapBFI(y_)

	tmp := newBFI()

	F := wrapBFI(b.F)

	// ls = yy + xy
	ls := newBFI()
	ls.Mul(y, y)    // ls = yy
	tmp.Mul(x, y)   //           xy
	ls.Add(ls, tmp) // ls = yy + xy
	ls.Mod(ls, F)   // ls = ls % f

	// xxx + axx + b
	xx := newBFI().Mul(x, x)

	rs := newBFI()
	rs.Mul(x, xx)             // rs = xxx
	tmp.Mul(wrapBFI(b.A), xx) //            axx
	rs.Add(rs, tmp)           // rs = xxx + axx
	rs.Add(rs, wrapBFI(b.B))  // rs = xxx + axx + b
	rs.Mod(rs, F)             // rs = rs % f

	return ls.Cmp(rs) == 0
}

func (b *BinaryCurveParams) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	// https://gist.github.com/kurtbrose/4423605#file-elliptic-py-L37-L45

	x, y = new(big.Int), new(big.Int)
	return add(x, y, x1, y1, x2, y2, b)
}

func add(x_, y_, px_, py_, qx_, qy_ *big.Int, c *BinaryCurveParams) (*big.Int, *big.Int) {
	// https://gist.github.com/kurtbrose/4423605#file-elliptic-py-L141-L155

	if px_.Sign() == 0 && py_.Sign() == 0 {
		x_.Set(qx_)
		y_.Set(qy_)
		return x_, y_
	}
	if qx_.Sign() == 0 && qy_.Sign() == 0 {
		x_.Set(px_)
		y_.Set(py_)
		return x_, y_
	}

	// if p == q: #point doubling
	if px_.Cmp(qx_) == 0 && py_.Cmp(qy_) == 0 {
		return double(x_, y_, px_, py_, c)
	}

	x := wrapBFI(x_)
	y := wrapBFI(y_)

	px, py := wrapBFI(px_), wrapBFI(py_)
	qx, qy := wrapBFI(qx_), wrapBFI(qy_)

	s := newBFI()
	f := wrapBFI(c.F)
	a := wrapBFI(c.A)

	tmp := newBFI()

	// s = _divmod(p.y + q.y, p.x + q.x, f)
	s.Add(py, qy)       //             s = p.y + q.y
	tmp.Add(px, qx)     //                            tmp = p.x + q.x
	s.DivMod(s, tmp, f) // s = _divmod(s            , tmp            , f)

	// x = s*s + s + p.x + q.x + a
	x.Mul(s, s)  // x = ss
	x.Add(x, s)  // x = ss + s
	x.Add(x, px) // x = ss + s + p.x
	x.Add(x, qx) // x = ss + s + p.x + q.x
	x.Add(x, a)  // x = ss + s + p.x + q.x + a
	x.Mod(x, f)  // x = x % f

	// y = s*(p.x + x) + x + p.y
	tmp.Add(px, x) //   tmp = (p.x + x)
	y.Mul(s, tmp)  // y = s * (p.x + x)
	y.Add(y, x)    // y = s * (p.x + x) + x
	y.Add(y, py)   // y = s * (p.x + x) + p.y
	y.Mod(y, f)    // y = y % f

	return x_, y_
}

func (b *BinaryCurveParams) Double(x1, y1 *big.Int) (x, y *big.Int) {
	x, y = new(big.Int), new(big.Int)
	return double(x, y, x1, y1, b)
}

func double(x_, y_, px_, py_ *big.Int, c *BinaryCurveParams) (*big.Int, *big.Int) {
	// https://gist.github.com/kurtbrose/4423605#file-elliptic-py-L148-L150

	x, y := wrapBFI(x_), wrapBFI(y_)
	px, py := wrapBFI(px_), wrapBFI(py_)

	s := newBFI()
	f := wrapBFI(c.F)
	a := wrapBFI(c.A)

	// s = p.x + _divmod(p.y, p.x, f)
	s.DivMod(py, px, f) // s =       _divmod(p.y, p.x, f)
	s.Add(px, s)        // s = p.x + _divmod(p.y, p.x, f)

	// x = s*s + s + a
	x.Mul(s, s) // x = ss
	x.Add(x, s) // x = ss + s
	x.Add(x, a) // x = ss + s + a
	x.Mod(x, f) // x = x % f

	// y = p.x*p.x + (s+1)*x
	y.Mul(px, px)          // y = p.x * p.x
	s.Add(s, wrapBFI(one)) //             s = (s + 1)
	s.Mul(s, x)            //             s = (s + 1) * x
	y.Add(y, s)            // y = p.x * p.x + (s + 1) * x
	y.Mod(y, f)            // y = y % f

	return x_, y_
}

func (b *BinaryCurveParams) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	// https://gist.github.com/kurtbrose/4423605#file-elliptic-py-L49-L59
	num := new(big.Int).SetBytes(k)

	// acc = 0 #TODO: what is zero for an EC_Point?
	accX, accY := new(big.Int), new(big.Int)

	// doubler = self
	doublerX, doublerY := new(big.Int).Set(x1), new(big.Int).Set(y1)

	tmpX, tmpY := new(big.Int), new(big.Int)

	// while num >= 1:
	for num.Sign() > 0 {
		// if num & 1:
		if num.Bit(0) != 0 {
			// acc += doubler
			tmpX.Set(accX)
			tmpY.Set(accY)
			add(accX, accY, tmpX, tmpY, doublerX, doublerY, b)
		}
		// num >>= 1
		num.Rsh(num, 1)

		// doubler += doubler
		tmpX.Set(doublerX)
		tmpY.Set(doublerY)
		double(doublerX, doublerY, tmpX, tmpY, b)
	}

	return accX, accY
}

func (b *BinaryCurveParams) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return b.ScalarMult(b.Gx, b.Gy, k)
}
