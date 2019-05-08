package fourq

import (
	"fmt"
)

// fieldElem implements a field of size p² as a quadratic extension of the base
// field where i²=-1.
type fieldElem struct {
	x, y baseFieldElem // value is x+yi.
}

func newFieldElem() *fieldElem {
	return &fieldElem{}
}

func (e *fieldElem) String() string {
	return fmt.Sprintf("[%v, %v]", &e.x, &e.y)
}

func (e *fieldElem) GoString() string {
	return fmt.Sprintf("fieldElem{x: %#v, y: %#v}", &e.x, &e.y)
}

func (e *fieldElem) Set(a *fieldElem) *fieldElem {
	e.x.Set(&a.x)
	e.y.Set(&a.y)
	return e
}

func (e *fieldElem) SetOne() {
	e.x.SetOne()
	e.y.SetZero()
}

func (e *fieldElem) IsZero() bool {
	return e.x.IsZero() && e.y.IsZero()
}

func (e *fieldElem) Neg(a *fieldElem) *fieldElem {
	e.x.Neg(&a.x)
	e.y.Neg(&a.y)
	return e
}

func (e *fieldElem) Invert(a *fieldElem) *fieldElem {
	t1 := newBaseFieldElem()
	t2 := newBaseFieldElem()

	bfeSquare(t1, &a.x)
	bfeSquare(t2, &a.y)
	bfeAdd(t1, t1, t2)
	t1.Invert(t1)

	bfeMul(&e.x, &a.x, t1)

	t1.Neg(t1)
	bfeMul(&e.y, &a.y, t1)

	return e
}

func (e *fieldElem) reduce() {
	e.x.reduce()
	e.y.reduce()
}

// sign returns the "sign" of e -- either 0 or 1, used to distinguish e from -e.
func (e *fieldElem) sign() uint64 {
	if e.x.IsZero() {
		return e.y[1] >> 62
	}
	return e.x[1] >> 62
}

//go:noescape
func feDbl(c, a *fieldElem)

//go:noescape
func feAdd(c, a, b *fieldElem)

//go:noescape
func feSub(c, a, b *fieldElem)

//go:noescape
func feMul(c, a, b *fieldElem)

//go:noescape
func feSquare(c, a *fieldElem)
