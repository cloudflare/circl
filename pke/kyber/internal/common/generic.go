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
