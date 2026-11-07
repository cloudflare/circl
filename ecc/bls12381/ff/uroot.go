package ff

// URootSize is the length in bytes of a root of unit.
const URootSize = Fp12Size

// URoot represents an n-th root of unit, that is an element x in Cyclo6 such
// that x^n=1, where n = ScalarOrder().
type URoot Cyclo6

func (z URoot) String() string                 { return (Cyclo6)(z).String() }
func (z URoot) MarshalBinary() ([]byte, error) { return (Fp12)(z).MarshalBinary() }
func (z *URoot) SetIdentity()                  { (*Fp12)(z).SetOne() }
func (z URoot) IsEqual(x *URoot) int           { return (Cyclo6)(z).IsEqual((*Cyclo6)(x)) }
func (z URoot) IsIdentity() int                { i := &URoot{}; i.SetIdentity(); return z.IsEqual(i) }
func (z *URoot) Exp(x *URoot, n []byte)        { (*Cyclo6)(z).exp((*Cyclo6)(x), n) }
func (z *URoot) Mul(x, y *URoot)               { (*Cyclo6)(z).Mul((*Cyclo6)(x), (*Cyclo6)(y)) }
func (z *URoot) Sqr(x *URoot)                  { (*Cyclo6)(z).Sqr((*Cyclo6)(x)) }
func (z *URoot) Inv(x *URoot)                  { (*Cyclo6)(z).Inv((*Cyclo6)(x)) }

// UnmarshalBinary sets z to the element encoded in b. It returns an error if
// the element is not an n-th root of unity, where n = ScalarOrder().
func (z *URoot) UnmarshalBinary(b []byte) error {
	var x URoot
	if err := (*Fp12)(&x).UnmarshalBinary(b); err != nil {
		return err
	}
	// NOTE Previous versions accepted any element of Fp12.
	if !x.isValid() {
		return errInputSubgroup
	}
	*z = x
	return nil
}

// isValid returns true if z is an n-th root of unity, where n = ScalarOrder().
//
// The n-th roots of unity form the subgroup of order n of the cyclotomic
// group, which has order Φ12(p) = p^4-p^2+1. As gcd(p-paramX, Φ12(p)) = n,
// a non-zero z with z^Φ12(p) = 1 is an n-th root of unity iff z^p = z^paramX.
func (z *URoot) isValid() bool {
	x := (*Fp12)(z)
	if x.IsZero() == 1 {
		return false
	}

	var xp2, xp4 Fp12
	xp2.Frob(x)
	xp2.Frob(&xp2) // xp2 = z^(p^2)
	xp4.Frob(&xp2)
	xp4.Frob(&xp4)   // xp4 = z^(p^4)
	xp4.Mul(&xp4, x) // xp4 = z^(p^4+1)
	if xp4.IsEqual(&xp2) != 1 {
		return false
	}

	// z is in Cyclo6, so PowToX can be used.
	var zp, zx Cyclo6
	zp.Frob((*Cyclo6)(z))
	zx.PowToX((*Cyclo6)(z))
	return zp.IsEqual(&zx) == 1
}
