package ff

// URootSize is the length in bytes of a root of unit.
const URootSize = Fp12Size

// URoot represents an n-th root of unit, that is an element x in Cyclo6 such
// that x^n=1, where n = ScalarOrder().
type URoot Cyclo6

func (z URoot) String() string                  { return (Cyclo6)(z).String() }
func (z *URoot) UnmarshalBinary(b []byte) error { return (*Fp12)(z).UnmarshalBinary(b) }
func (z URoot) MarshalBinary() ([]byte, error)  { return (Fp12)(z).MarshalBinary() }
func (z *URoot) SetIdentity()                   { (*Fp12)(z).SetOne() }
func (z URoot) IsEqual(x *URoot) int            { return (Cyclo6)(z).IsEqual((*Cyclo6)(x)) }
func (z URoot) IsIdentity() int                 { i := &URoot{}; i.SetIdentity(); return z.IsEqual(i) }
func (z *URoot) Exp(x *URoot, n []byte)         { (*Cyclo6)(z).exp((*Cyclo6)(x), n) }
func (z *URoot) Mul(x, y *URoot)                { (*Cyclo6)(z).Mul((*Cyclo6)(x), (*Cyclo6)(y)) }
func (z *URoot) Sqr(x *URoot)                   { (*Cyclo6)(z).Sqr((*Cyclo6)(x)) }
func (z *URoot) Inv(x *URoot)                   { (*Cyclo6)(z).Inv((*Cyclo6)(x)) }
