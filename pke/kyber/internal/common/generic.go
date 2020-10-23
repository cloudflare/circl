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
