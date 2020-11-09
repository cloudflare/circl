package group_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/internal/test"
)

func TestGroup(t *testing.T) {
	const testTimes = 1 << 8
	for _, g := range []group.Group{
		group.P256,
		group.P384,
		group.P521,
	} {
		g := g
		r := g.Random()
		n := g.(fmt.Stringer).String()
		t.Run(n+"/Add", func(tt *testing.T) { testAdd(tt, testTimes, g, r) })
		t.Run(n+"/Neg", func(tt *testing.T) { testNeg(tt, testTimes, g, r) })
		t.Run(n+"/Mul", func(tt *testing.T) { testMul(tt, testTimes, g, r) })
		t.Run(n+"/MulGen", func(tt *testing.T) { testMulGen(tt, testTimes, g, r) })
		t.Run(n+"/Order", func(tt *testing.T) { testOrder(tt, testTimes, g, r) })
		t.Run(n+"/Marshal", func(tt *testing.T) { testMarshal(tt, testTimes, g, r) })
		t.Run(n+"/Scalar", func(tt *testing.T) { testScalar(tt, testTimes, g, r) })
	}
}

func testAdd(t *testing.T, testTimes int, g group.Group, r group.Randomizer) {
	Q := g.NewElt()
	for i := 0; i < testTimes; i++ {
		P := r.RndElt(rand.Reader)

		got := Q.Dbl(P).Dbl(Q).Dbl(Q).Dbl(Q) // Q = 16P

		R := g.Identity()
		for j := 0; j < 16; j++ {
			R.Add(R, P)
		}
		want := R // R = 16P = P+P...+P
		if !got.IsEqual(want) {
			test.ReportError(t, got, want, P)
		}
	}
}

func testNeg(t *testing.T, testTimes int, g group.Group, r group.Randomizer) {
	Q := g.NewElt()
	for i := 0; i < testTimes; i++ {
		P := r.RndElt(rand.Reader)
		Q.Neg(P)
		Q.Add(Q, P)
		got := Q.IsIdentity()
		want := true
		if got != want {
			test.ReportError(t, got, want, P)
		}
	}
}

func testMul(t *testing.T, testTimes int, g group.Group, r group.Randomizer) {
	Q := g.NewElt()
	kInv := g.NewScl()
	for i := 0; i < testTimes; i++ {
		P := r.RndElt(rand.Reader)
		k := r.RndScl(rand.Reader)
		kInv.Inv(k)

		Q.Mul(P, k)
		Q.Mul(Q, kInv)

		got := P
		want := Q
		if !got.IsEqual(want) {
			test.ReportError(t, got, want, P, k)
		}
	}
}

func testMulGen(t *testing.T, testTimes int, g group.Group, r group.Randomizer) {
	G := g.Generator()
	P := g.NewElt()
	Q := g.NewElt()
	for i := 0; i < testTimes; i++ {
		k := r.RndScl(rand.Reader)

		P.Mul(G, k)
		Q.MulGen(k)

		got := P
		want := Q
		if !got.IsEqual(want) {
			test.ReportError(t, got, want, P, k)
		}
	}
}

func testOrder(t *testing.T, testTimes int, g group.Group, r group.Randomizer) {
	Q := g.NewElt()
	order := g.Order()
	for i := 0; i < testTimes; i++ {
		P := r.RndElt(rand.Reader)

		Q.Mul(P, order)
		got := Q.IsIdentity()
		want := true
		if got != want {
			test.ReportError(t, got, want, P)
		}
	}
}

func testMarshal(t *testing.T, testTimes int, g group.Group, r group.Randomizer) {
	I := g.Identity()
	got, _ := I.MarshalBinary()
	want := []byte{0}
	if !bytes.Equal(got, want) {
		test.ReportError(t, got, want)
	}
	got, _ = I.MarshalBinaryCompress()
	if !bytes.Equal(got, want) {
		test.ReportError(t, got, want)
	}
	II := g.NewElt()
	err := II.UnmarshalBinary(got)
	if err != nil || !I.IsEqual(II) {
		test.ReportError(t, I, II)
	}

	got1 := g.NewElt()
	got2 := g.NewElt()
	for i := 0; i < testTimes; i++ {
		x := r.RndElt(rand.Reader)
		enc1, _ := x.MarshalBinary()
		enc2, _ := x.MarshalBinaryCompress()

		err1 := got1.UnmarshalBinary(enc1)
		err2 := got2.UnmarshalBinary(enc2)
		if err1 != nil || !x.IsEqual(got1) {
			test.ReportError(t, got1, x)
		}
		if err2 != nil || !x.IsEqual(got2) {
			test.ReportError(t, got2, x)
		}
	}
}

func testScalar(t *testing.T, testTimes int, g group.Group, r group.Randomizer) {
	c := g.NewScl()
	d := g.NewScl()
	e := g.NewScl()
	f := g.NewScl()
	for i := 0; i < testTimes; i++ {
		a := r.RndScl(rand.Reader)
		b := r.RndScl(rand.Reader)
		c.Add(a, b)
		d.Sub(a, b)
		e.Mul(c, d)

		c.Mul(a, a)
		d.Mul(b, b)
		d.Neg(d)
		f.Add(c, d)
		enc1, err1 := e.MarshalBinary()
		enc2, err2 := f.MarshalBinary()
		if err1 != nil || err2 != nil || !bytes.Equal(enc1, enc2) {
			test.ReportError(t, enc1, enc2, a, b)
		}
	}
}

func BenchmarkElement(b *testing.B) {
	for _, g := range []group.Group{
		group.P256,
		group.P384,
		group.P521,
	} {
		r := g.Random()
		x := r.RndElt(rand.Reader)
		y := r.RndElt(rand.Reader)
		n := r.RndScl(rand.Reader)
		name := g.(fmt.Stringer).String()
		b.Run(name+"/Add", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Add(x, y)
			}
		})
		b.Run(name+"/Dbl", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Dbl(x)
			}
		})
		b.Run(name+"/Mul", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				y.Mul(x, n)
			}
		})
		b.Run(name+"/MulGen", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.MulGen(n)
			}
		})
	}
}

func BenchmarkScalar(b *testing.B) {
	for _, g := range []group.Group{
		group.P256,
		group.P384,
		group.P521,
	} {
		r := g.Random()
		x := r.RndScl(rand.Reader)
		y := r.RndScl(rand.Reader)
		name := g.(fmt.Stringer).String()
		b.Run(name+"/Add", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Add(x, y)
			}
		})
		b.Run(name+"/Mul", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x.Mul(x, y)
			}
		})
		b.Run(name+"/Inv", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				y.Inv(x)
			}
		})
	}
}
