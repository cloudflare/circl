// Package polynomial provides representations of polynomials over the scalars
// of a group.
package polynomial

import "github.com/cloudflare/circl/group"

// Polynomial stores a polynomial over the set of scalars of a group.
type Polynomial struct {
	// Internal representation is in polynomial basis:
	// Thus,
	//     p(x) = \sum_i^k c[i] x^i,
	// where k = len(c)-1 is the degree of the polynomial.
	c []group.Scalar
}

// New creates a new polynomial given its coefficients in ascending order.
// Thus,
//
//	p(x) = \sum_i^k c[i] x^i,
//
// where k = len(c)-1 is the degree of the polynomial.
//
// The zero polynomial has degree equal to -1 and can be instantiated passing
// nil to New.
func New(coeffs []group.Scalar) (p Polynomial) {
	if l := len(coeffs); l != 0 {
		p.c = make([]group.Scalar, l)
		for i := range coeffs {
			p.c[i] = coeffs[i].Copy()
		}
	}

	return
}

func (p Polynomial) Degree() int {
	i := len(p.c) - 1
	for i > 0 && p.c[i].IsZero() {
		i--
	}
	return i
}

func (p Polynomial) Evaluate(x group.Scalar) group.Scalar {
	px := x.Group().NewScalar()
	if l := len(p.c); l != 0 {
		px.Set(p.c[l-1])
		for i := l - 2; i >= 0; i-- {
			px.Mul(px, x)
			px.Add(px, p.c[i])
		}
	}
	return px
}

// LagrangePolynomial stores a Lagrange polynomial over the set of scalars of a group.
type LagrangePolynomial struct {
	// Internal representation is in Lagrange basis:
	// Thus,
	//     p(x) = \sum_i^k y[i] L_j(x), where k is the degree of the polynomial,
	//     L_j(x) = \prod_i^k (x-x[i])/(x[j]-x[i]),
	//     y[i] = p(x[i]), and
	//     all x[i] are different.
	x, y []group.Scalar
}

// NewLagrangePolynomial creates a polynomial in Lagrange basis given a list
// of nodes (x) and values (y), such that:
//
//	p(x) = \sum_i^k y[i] L_j(x), where k is the degree of the polynomial,
//	L_j(x) = \prod_i^k (x-x[i])/(x[j]-x[i]),
//	y[i] = p(x[i]), and
//	all x[i] are different.
//
// It panics if one of these conditions does not hold.
//
// The zero polynomial has degree equal to -1 and can be instantiated passing
// (nil,nil) to NewLagrangePolynomial.
func NewLagrangePolynomial(x, y []group.Scalar) (l LagrangePolynomial) {
	if len(x) != len(y) {
		panic("lagrange: invalid length")
	}

	if !areAllDifferent(x) {
		panic("lagrange: x[i] must be different")
	}

	if n := len(x); n != 0 {
		l.x, l.y = make([]group.Scalar, n), make([]group.Scalar, n)
		for i := range x {
			l.x[i], l.y[i] = x[i].Copy(), y[i].Copy()
		}
	}

	return
}

func (l LagrangePolynomial) Degree() int { return len(l.x) - 1 }

func (l LagrangePolynomial) Evaluate(x group.Scalar) group.Scalar {
	px := x.Group().NewScalar()
	tmp := x.Group().NewScalar()
	for i := range l.x {
		LjX := baseRatio(uint(i), l.x, x)
		tmp.Mul(l.y[i], LjX)
		px.Add(px, tmp)
	}

	return px
}

// LagrangeBase returns the j-th Lagrange polynomial base evaluated at x.
// Thus, L_j(x) = \prod (x - x[i]) / (x[j] - x[i]) for 0 <= i < k, and i != j.
func LagrangeBase(jth uint, xi []group.Scalar, x group.Scalar) group.Scalar {
	if jth >= uint(len(xi)) {
		panic("lagrange: invalid index")
	}
	return baseRatio(jth, xi, x)
}

func baseRatio(jth uint, xi []group.Scalar, x group.Scalar) group.Scalar {
	num := x.Copy()
	num.SetUint64(1)
	den := x.Copy()
	den.SetUint64(1)

	tmp := x.Copy()
	for i := range xi {
		if uint(i) != jth {
			num.Mul(num, tmp.Sub(x, xi[i]))
			den.Mul(den, tmp.Sub(xi[jth], xi[i]))
		}
	}

	return num.Mul(num, den.Inv(den))
}

func areAllDifferent(x []group.Scalar) bool {
	m := make(map[string]struct{})
	for i := range x {
		k, err := x[i].MarshalBinary()
		if err != nil {
			panic(err)
		}
		if _, exists := m[string(k)]; exists {
			return false
		}
		m[string(k)] = struct{}{}
	}
	return true
}
