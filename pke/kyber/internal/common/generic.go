// +build !amd64

package common

// Sets p to a + b.  Does not normalize coefficients.
func (p *Poly) Add(a, b *Poly) {
	p.addGeneric(a, b)
}

// Sets p to a - b.  Does not normalize coefficients.
func (p *Poly) Sub(a, b *Poly) {
	p.subGeneric(a, b)
}

// Executes an in-place forward "NTT" on p.
//
// Assumes the coefficients are in absolute value ≤q.  The resulting
// coefficients are in absolute value ≤7q.  If the input is in Montgomery
// form, then the result is in Montgomery form and so (by linearity of the NTT)
// if the input is in regular form, then the result is also in regular form.
func (p *Poly) NTT() {
	p.nttGeneric()
}

// Executes an in-place inverse "NTT" on p and multiply by the Montgomery
// factor R.
//
// Assumes the coefficients are in absolute value ≤q.  The resulting
// coefficients are in absolute value ≤q.  If the input is in Montgomery
// form, then the result is in Montgomery form and so (by linearity)
// if the input is in regular form, then the result is also in regular form.
func (p *Poly) InvNTT() {
	p.invNTTGeneric()
}

// Sets p to the "pointwise" multiplication of a and b.
//
// That is: InvNTT(p) = InvNTT(a) * InvNTT(b).  Assumes a and b are in
// Montgomery form.  Products between coefficients of a and b must be strictly
// bounded in absolute value by 2¹⁵q.  p will be in Montgomery form and
// bounded in absolute value by 2q.
func (p *Poly) MulHat(a, b *Poly) {
	p.mulHatGeneric(a, b)
}
