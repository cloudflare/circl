// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package brainpool

import (
	"crypto/elliptic"
	"encoding/asn1"
	"math/big"
)

type rcurve struct {
	twisted elliptic.Curve
	params  elliptic.CurveParams
	z       *big.Int
	zinv    *big.Int
	z2      *big.Int
	z3      *big.Int
	zinv2   *big.Int
	zinv3   *big.Int
	oid     asn1.ObjectIdentifier
}

func newrcurve(name string, twisted elliptic.Curve, gx, gy, z *big.Int, oid asn1.ObjectIdentifier) *rcurve {
	var curve rcurve

	curve.twisted = twisted
	curve.params = *twisted.Params()
	curve.params.B = nil // FIXME: crypto/elliptic assumes A=-3
	curve.params.Gx = gx
	curve.params.Gy = gy
	curve.params.Name = name

	two := big.NewInt(2)
	three := big.NewInt(3)

	curve.z = z
	curve.zinv = new(big.Int).ModInverse(z, curve.params.P)
	curve.z2 = new(big.Int).Exp(curve.z, two, curve.params.P)
	curve.z3 = new(big.Int).Exp(curve.z, three, curve.params.P)
	curve.zinv2 = new(big.Int).Exp(curve.zinv, two, curve.params.P)
	curve.zinv3 = new(big.Int).Exp(curve.zinv, three, curve.params.P)

	curve.oid = oid

	return &curve
}

func (curve *rcurve) toTwisted(x, y *big.Int) (*big.Int, *big.Int) {
	var tx, ty big.Int
	tx.Mul(x, curve.z2)
	tx.Mod(&tx, curve.params.P)
	ty.Mul(y, curve.z3)
	ty.Mod(&ty, curve.params.P)
	return &tx, &ty
}

func (curve *rcurve) fromTwisted(tx, ty *big.Int) (*big.Int, *big.Int) {
	var x, y big.Int
	x.Mul(tx, curve.zinv2)
	x.Mod(&x, curve.params.P)
	y.Mul(ty, curve.zinv3)
	y.Mod(&y, curve.params.P)
	return &x, &y
}

func (curve *rcurve) Oid() asn1.ObjectIdentifier {
	return curve.oid
}

func (curve *rcurve) Params() *elliptic.CurveParams {
	return &curve.params
}

func (curve *rcurve) IsOnCurve(x, y *big.Int) bool {
	return curve.twisted.IsOnCurve(curve.toTwisted(x, y))
}

func (curve *rcurve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	tx1, ty1 := curve.toTwisted(x1, y1)
	tx2, ty2 := curve.toTwisted(x2, y2)
	return curve.fromTwisted(curve.twisted.Add(tx1, ty1, tx2, ty2))
}

func (curve *rcurve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	return curve.fromTwisted(curve.twisted.Double(curve.toTwisted(x1, y1)))
}

func (curve *rcurve) ScalarMult(x1, y1 *big.Int, scalar []byte) (x, y *big.Int) {
	tx1, ty1 := curve.toTwisted(x1, y1)
	return curve.fromTwisted(curve.twisted.ScalarMult(tx1, ty1, scalar))
}

func (curve *rcurve) ScalarBaseMult(scalar []byte) (x, y *big.Int) {
	return curve.fromTwisted(curve.twisted.ScalarBaseMult(scalar))
}
