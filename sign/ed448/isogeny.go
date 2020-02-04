package ed448

import fp "github.com/cloudflare/circl/math/fp448"

// deg4isogeny is a 4-degree isogeny from Goldilocks curve to an isogenous
// twisted Edwards curve with a=-1.
// Goldilocks is x^2+y^2=1-39081x^2y^2
// 4IsoCurve is -x^2+y^2=1-39082x^2y^2
type deg4isogeny struct{}

// Push sends a point in Goldilocks to a point in 4IsoCurve.
func (m deg4isogeny) Push(p *pointR1) { m.calculate(p, false) }

// Push sends a point in 4IsoCurve to a point in Goldilocks.
func (m deg4isogeny) Pull(p *pointR1) { m.calculate(p, true) }

func (m deg4isogeny) calculate(P *pointR1, aNegative bool) {
	Px, Py, Pz, Pta, Ptb := &P.x, &P.y, &P.z, &P.ta, &P.tb
	a, b, c, d, e, f, g, h := Px, Py, Pz, &fp.Elt{}, Pta, Px, Py, Ptb
	fp.Add(e, Px, Py) // x+y
	fp.Sqr(a, Px)     // A = x^2
	fp.Sqr(b, Py)     // B = y^2
	fp.Sqr(c, Pz)     // z^2
	fp.Add(c, c, c)   // C = 2*z^2
	*d = *a
	if aNegative { // D = a*A
		fp.Neg(d, a)
	}
	fp.Sqr(e, e)     // (x+y)^2
	fp.Sub(e, e, a)  // (x+y)^2-A
	fp.Sub(e, e, b)  // E = (x+y)^2-A-B
	fp.Add(h, b, d)  // H = B+D
	fp.Sub(g, b, d)  // G = B-D
	fp.Sub(f, c, h)  // F = C-H
	fp.Mul(Pz, f, g) // Z = F * G
	fp.Mul(Px, e, f) // X = E * F
	fp.Mul(Py, g, h) // Y = G * H, // T = E * H
}
