package fourq

import (
	"fmt"
)

type point struct {
	x, y, z, t fieldElem
}

func newPoint() *point {
	pt := &point{}
	pt.y.x[0] = 1
	pt.z.x[0] = 1
	return pt
}

func (c *point) String() string {
	return fmt.Sprintf("point(\n\tx: %v,\n\ty: %v,\n\tz: %v,\n\tt: %v\n)", &c.x, &c.y, &c.z, &c.t)
}

func (c *point) GoString() string {
	return fmt.Sprintf("&point{\n\tx: %#v,\n\ty: %#v,\n\tz: %#v,\n\tt: %#v,\n}", &c.x, &c.y, &c.z, &c.t)
}

func (c *point) Set(a *point) *point {
	c.x.Set(&a.x)
	c.y.Set(&a.y)
	c.t.Set(&a.t)
	c.z.Set(&a.z)
	return c
}

// SetBytes decompresses the point pt and stores it in c. It returns c and
// true if decompression succeeded; false if not.
func (c *point) SetBytes(pt [32]byte) (*point, bool) {
	c.y.x.SetBytes(pt[:16])
	c.y.y.SetBytes(pt[16:])
	c.z.SetOne()

	// Separate p.y from the sign of x.
	var s uint64
	s, c.y.y[1] = uint64(c.y.y[1])>>63, c.y.y[1]&aMask

	if c.y.x[1]>>63 == 1 {
		return nil, false
	}

	// Recover x coordinate from y, up to a multiple of plus/minus one.
	u, v := newFieldElem(), newFieldElem()
	feSquare(u, &c.y)
	feSub(u, u, one)

	feSquare(v, &c.y)
	feMul(v, v, d)
	feAdd(v, v, one)

	t0, temp := newBaseFieldElem(), newBaseFieldElem()
	bfeMul(t0, &u.x, &v.x)
	bfeMul(temp, &u.y, &v.y)
	bfeAdd(t0, t0, temp)

	t1 := newBaseFieldElem()
	bfeMul(t1, &u.y, &v.x)
	bfeMul(temp, &u.x, &v.y)
	bfeSub(t1, temp, t1)

	t2 := newBaseFieldElem()
	bfeSquare(t2, &v.x)
	bfeSquare(temp, &v.y)
	bfeAdd(t2, t2, temp)

	t3 := newBaseFieldElem()
	bfeSquare(t3, t0)
	bfeSquare(temp, t1)
	bfeAdd(t3, t3, temp)
	for i := 0; i < 125; i++ {
		bfeSquare(t3, t3)
	}

	t := newBaseFieldElem()
	bfeAdd(t, t0, t3)
	t.reduce()
	if t.IsZero() {
		bfeSub(t, t0, t3)
	}
	bfeDbl(t, t)

	a := newBaseFieldElem()
	bfeSquare(a, t2)
	bfeMul(a, a, t2)
	bfeMul(a, a, t)
	a.chain1251(a)

	b := newBaseFieldElem()
	bfeMul(b, a, t2)
	bfeMul(b, b, t)

	bfeHalf(&c.x.x, b)
	bfeMul(&c.x.y, a, t2)
	bfeMul(&c.x.y, &c.x.y, t1)

	// Recover x-coordinate exactly.
	bfeSquare(temp, b)
	bfeMul(temp, temp, t2)
	if *temp != *t {
		c.x.x, c.x.y = c.x.y, c.x.x
	}
	if c.x.sign() != s {
		c.x.Neg(&c.x)
	}
	if !c.IsOnCurve() {
		c.x.y.Neg(&c.x.y)
	}

	// Finally, verify point is valid and return.
	if !c.IsOnCurve() {
		return nil, false
	}

	feMul(&c.t, &c.x, &c.y)
	return c, true
}

// SetBytesU returns c and true if pt represents an uncompressed point on the
// curve; false if not.
func (c *point) SetBytesU(pt [64]byte) (*point, bool) {
	c.x.x.SetBytes(pt[:16])
	c.x.y.SetBytes(pt[16:32])
	c.y.x.SetBytes(pt[32:48])
	c.y.y.SetBytes(pt[48:])

	if !c.IsOnCurve() {
		return nil, false
	}

	c.z.SetOne()
	feMul(&c.t, &c.x, &c.y)
	return c, true
}

// Bytes returns c, compressed into a [32]byte.
func (c *point) Bytes() (out [32]byte) {
	c.MakeAffine()
	c.y.y[1] += c.x.sign() << 63

	x, y := c.y.x.Bytes(), c.y.y.Bytes()
	copy(out[:16], x[:])
	copy(out[16:], y[:])
	return
}

// BytesU returns c, as an uncompressed [64]byte.
func (c *point) BytesU() (out [64]byte) {
	c.MakeAffine()

	xx, xy := c.x.x.Bytes(), c.x.y.Bytes()
	yx, yy := c.y.x.Bytes(), c.y.y.Bytes()
	copy(out[0:16], xx[:])
	copy(out[16:32], xy[:])
	copy(out[32:48], yx[:])
	copy(out[48:], yy[:])
	return
}

func (c *point) IsOnCurve() bool {
	x2, y2 := newFieldElem(), newFieldElem()
	feSquare(x2, &c.x)
	feSquare(y2, &c.y)

	lhs := newFieldElem()
	feSub(lhs, y2, x2)

	rhs := newFieldElem()
	feMul(rhs, &c.x, &c.y)
	feSquare(rhs, rhs)
	feMul(rhs, rhs, d)
	feAdd(rhs, rhs, one)

	feSub(lhs, lhs, rhs)
	lhs.reduce()
	return lhs.IsZero()
}

func (c *point) MakeAffine() {
	zInv := newFieldElem().Invert(&c.z)

	feMul(&c.x, &c.x, zInv)
	feMul(&c.y, &c.y, zInv)
	c.z.SetOne()
	feMul(&c.t, &c.x, &c.y)

	c.x.reduce()
	c.y.reduce()
	c.t.reduce()
}

//go:noescape
func pDbl(a *point)

//go:noescape
func pMixedAdd(a, b *point)
