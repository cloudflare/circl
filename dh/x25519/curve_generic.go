// +build !amd64

package x25519

import (
	"encoding/binary"
	"math/bits"

	fp255 "github.com/cloudflare/circl/math/fp25519"
)

func (c *curve) ladderStep(w *[5]fp255.Elt, b uint) {
	x1, x2, z2, x3, z3 := &w[0], &w[1], &w[2], &w[3], &w[4]
	t0 := &fp255.Elt{}
	t1 := &fp255.Elt{}
	fp255.AddSub(x2, z2)
	fp255.AddSub(x3, z3)
	fp255.Mul(t0, x2, z3)
	fp255.Mul(t1, x3, z2)
	fp255.AddSub(t0, t1)
	fp255.Cmov(x2, x3, b)
	fp255.Cmov(z2, z3, b)
	fp255.Sqr(x3, t0)
	fp255.Sqr(z3, t1)
	fp255.Mul(z3, x1, z3)
	fp255.Sqr(x2, x2)
	fp255.Sqr(z2, z2)
	fp255.Sub(t0, x2, z2)
	c.mulA24(t1, t0)
	fp255.Add(t1, t1, z2)
	fp255.Mul(x2, x2, z2)
	fp255.Mul(z2, t0, t1)
}

func (c *curve) mulA24(z, x *fp255.Elt) {
	const A24 = 121666
	const n = 8
	var xx [4]uint64
	for i := range xx {
		xx[i] = binary.LittleEndian.Uint64(x[i*n : (i+1)*n])
	}

	h0, l0 := bits.Mul64(xx[0], A24)
	h1, l1 := bits.Mul64(xx[1], A24)
	h2, l2 := bits.Mul64(xx[2], A24)
	h3, l3 := bits.Mul64(xx[3], A24)

	var c3 uint64
	l1, c0 := bits.Add64(h0, l1, 0)
	l2, c1 := bits.Add64(h1, l2, c0)
	l3, c2 := bits.Add64(h2, l3, c1)
	l4, _ := bits.Add64(h3, 0, c2)
	_, l4 = bits.Mul64(l4, 38)
	l0, c0 = bits.Add64(l0, l4, 0)
	xx[1], c1 = bits.Add64(l1, 0, c0)
	xx[2], c2 = bits.Add64(l2, 0, c1)
	xx[3], c3 = bits.Add64(l3, 0, c2)
	xx[0], _ = bits.Add64(l0, (-c3)&38, 0)
	for i := range xx {
		binary.LittleEndian.PutUint64(z[i*n:(i+1)*n], xx[i])
	}
}

func (c *curve) double(x, z *fp255.Elt) {
	t0, t1 := &fp255.Elt{}, &fp255.Elt{}
	fp255.AddSub(x, z)
	fp255.Sqr(x, x)
	fp255.Sqr(z, z)
	fp255.Sub(t0, x, z)
	c.mulA24(t1, t0)
	fp255.Add(t1, t1, z)
	fp255.Mul(x, x, z)
	fp255.Mul(z, t0, t1)
}

func (c *curve) difAdd(w *[5]fp255.Elt, b uint) {
	mu, x1, z1, x2, z2 := &w[0], &w[1], &w[2], &w[3], &w[4]
	fp255.Cswap(x1, x2, b)
	fp255.Cswap(z1, z2, b)
	fp255.AddSub(x1, z1)
	fp255.Mul(z1, z1, mu)
	fp255.AddSub(x1, z1)
	fp255.Sqr(x1, x1)
	fp255.Sqr(z1, z1)
	fp255.Mul(x1, x1, z2)
	fp255.Mul(z1, z1, x2)
}
