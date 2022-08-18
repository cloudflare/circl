package polynomial_test

import (
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/math/polynomial"
)

func TestPolyDegree(t *testing.T) {
	g := group.P256

	t.Run("zeroPoly", func(t *testing.T) {
		p := polynomial.New(nil)
		test.CheckOk(p.Degree() == -1, "it should be -1", t)
		p = polynomial.New([]group.Scalar{})
		test.CheckOk(p.Degree() == -1, "it should be -1", t)
	})

	t.Run("constantPoly", func(t *testing.T) {
		c := []group.Scalar{
			g.NewScalar().SetUint64(0),
			g.NewScalar().SetUint64(0),
		}
		p := polynomial.New(c)
		test.CheckOk(p.Degree() == 0, "it should be 0", t)
	})

	t.Run("linearPoly", func(t *testing.T) {
		c := []group.Scalar{
			g.NewScalar().SetUint64(0),
			g.NewScalar().SetUint64(1),
			g.NewScalar().SetUint64(0),
		}
		p := polynomial.New(c)
		test.CheckOk(p.Degree() == 1, "it should be 1", t)
	})
}

func TestPolyEval(t *testing.T) {
	g := group.P256
	c := []group.Scalar{
		g.NewScalar(),
		g.NewScalar(),
		g.NewScalar(),
	}
	c[0].SetUint64(5)
	c[1].SetUint64(5)
	c[2].SetUint64(2)
	p := polynomial.New(c)

	x := g.NewScalar()
	x.SetUint64(10)

	got := p.Evaluate(x)
	want := g.NewScalar()
	want.SetUint64(255)
	if !got.IsEqual(want) {
		test.ReportError(t, got, want)
	}
}

func TestLagrange(t *testing.T) {
	g := group.P256
	c := []group.Scalar{
		g.NewScalar(),
		g.NewScalar(),
		g.NewScalar(),
	}
	c[0].SetUint64(1234)
	c[1].SetUint64(166)
	c[2].SetUint64(94)
	p := polynomial.New(c)

	x := []group.Scalar{g.NewScalar(), g.NewScalar(), g.NewScalar()}
	x[0].SetUint64(2)
	x[1].SetUint64(4)
	x[2].SetUint64(5)

	y := []group.Scalar{}
	for i := range x {
		y = append(y, p.Evaluate(x[i]))
	}

	zero := g.NewScalar()
	l := polynomial.NewLagrangePolynomial(x, y)
	test.CheckOk(l.Degree() == p.Degree(), "bad degree", t)

	got := l.Evaluate(zero)
	want := p.Evaluate(zero)

	if !got.IsEqual(want) {
		test.ReportError(t, got, want)
	}

	// Test Kronecker's delta of LagrangeBase.
	// Thus:
	//    L_j(x[i]) = { 1, if i == j;
	//                { 0, otherwise.
	one := g.NewScalar()
	one.SetUint64(1)
	for j := range x {
		for i := range x {
			got := polynomial.LagrangeBase(uint(j), x, x[i])

			if i == j {
				want = one
			} else {
				want = zero
			}

			if !got.IsEqual(want) {
				test.ReportError(t, got, want)
			}
		}
	}

	// Test that inputs are different length
	err := test.CheckPanic(func() { polynomial.NewLagrangePolynomial(x, y[:1]) })
	test.CheckNoErr(t, err, "should panic")

	// Test that nodes must be different.
	x[0].Set(x[1])
	err = test.CheckPanic(func() { polynomial.NewLagrangePolynomial(x, y) })
	test.CheckNoErr(t, err, "should panic")

	// Test LagrangeBase wrong index
	err = test.CheckPanic(func() { polynomial.LagrangeBase(10, x, zero) })
	test.CheckNoErr(t, err, "should panic")
}
