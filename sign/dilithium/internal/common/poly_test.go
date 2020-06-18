package common

import (
	"math/rand"
	"testing"
)

func TestExceeds(t *testing.T) {
	for i := 0; i < N; i++ {
		var p Poly
		for v := 0; v < 10; v++ {
			p[i] = uint32(v)
			if p.Exceeds(uint32(10)) {
				t.Fatal()
			}
			p[i] = Q - uint32(v)
			if p.Exceeds(uint32(10)) {
				t.Fatal()
			}
		}
		for v := 10; v < 20; v++ {
			p[i] = uint32(v)
			if !p.Exceeds(uint32(10)) {
				t.Fatal()
			}
			p[i] = Q - uint32(v)
			if !p.Exceeds(uint32(10)) {
				t.Fatal()
			}
		}
	}
}

func TestMakeHintAgainstGeneric(t *testing.T) {
	var p0, p1, h1, h2 Poly
	for i := 0; i < 255; i++ {
		if i&3 == 1 {
			p0[i] = Gamma2 / 2
		} else if i&3 == 2 {
			p0[i] = Q - Gamma2/2
		} else if i&3 == 0 {
			p0[i] = Q - Gamma2
		} else {
			p0[i] = 2 * Gamma2
		}

		if (i>>2)&1 == 1 {
			p1[i] = 1234
		} else {
			p1[i] = 0
		}
	}

	pop1 := h1.makeHintGeneric(&p0, &p1)
	pop2 := h2.MakeHint(&p0, &p1)
	if h1 != h2 {
		t.Fatal()
	}
	if pop1 != pop2 {
		t.Fatal()
	}
}

func TestComposeAgainstGeneric(t *testing.T) {
	for k := 0; k < 1000; k++ {
		var p, a0, b0, a1, b1 Poly
		p.RandLe2Q()
		p.Normalize()
		p.Decompose(&a0, &a1)
		p.decomposeGeneric(&b0, &b1)
		if a0 != b0 && a1 != b1 {
			t.Fatal()
		}
	}
}

func TestSubAgainstGeneric(t *testing.T) {
	for k := 0; k < 1000; k++ {
		var p1, p2, a, b Poly
		a.RandLe2Q()
		b.RandLe2Q()
		p1.Sub(&a, &b)
		p2.subGeneric(&a, &b)
		if p1 != p2 {
			t.Fatalf("Sub(%v, %v) =\n%v\n!= %v", a, b, p1, p2)
		}
	}
}

func TestAddAgainstGeneric(t *testing.T) {
	for k := 0; k < 1000; k++ {
		var p1, p2, a, b Poly
		a.RandLe2Q()
		b.RandLe2Q()
		p1.Add(&a, &b)
		p2.addGeneric(&a, &b)
		if p1 != p2 {
			t.Fatalf("Add(%v, %v) =\n%v\n!= %v", a, b, p1, p2)
		}
	}
}

func TestMulHatAgainstGeneric(t *testing.T) {
	for k := 0; k < 1000; k++ {
		var p1, p2, a, b Poly
		a.RandLe2Q()
		b.RandLe2Q()
		p1.MulHat(&a, &b)
		p2.mulHatGeneric(&a, &b)
		if p1 != p2 {
			t.Fatalf("MulHat(%v, %v) =\n%v\n!= %v", a, b, p1, p2)
		}
	}
}

func TestReduceLe2QAgainstGeneric(t *testing.T) {
	for k := 0; k < 1000; k++ {
		var a Poly
		for j := 0; j < N; j++ {
			a[j] = rand.Uint32()
		}
		p1 := a
		p2 := a
		p1.reduceLe2QGeneric()
		p2.ReduceLe2Q()
		if p1 != p2 {
			t.Fatalf("%v !=\n%v", p1, p2)
		}
	}
}

func TestNormalizeAgainstGeneric(t *testing.T) {
	for k := 0; k < 1000; k++ {
		var a Poly
		for j := 0; j < N; j++ {
			a[j] = rand.Uint32()
		}
		p1 := a
		p2 := a
		p1.normalizeGeneric()
		p2.Normalize()
		if p1 != p2 {
			t.Fatalf("%v !=\n%v", p1, p2)
		}
	}
}

func TestMulBy2ToDAgainstGeneric(t *testing.T) {
	for k := 0; k < 1000; k++ {
		var p1, p2, q Poly
		q.RandLe2Q()
		p1.mulBy2toDGeneric(&q)
		p2.MulBy2toD(&q)
		if p1 != p2 {
			t.Fatalf("MulBy2ToD(%v) =\n%v\n!= %v", q, p1, p2)
		}
	}
}

func BenchmarkNormalizeGeneric(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.normalizeGeneric()
	}
}

func BenchmarkMulHatGeneric(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.mulHatGeneric(&p, &p)
	}
}

func BenchmarkAddGeneric(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.addGeneric(&p, &p)
	}
}

func BenchmarkSubGeneric(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.subGeneric(&p, &p)
	}
}

func BenchmarkReduceLe2QGeneric(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.reduceLe2QGeneric()
	}
}

func BenchmarkNormalizeAssumingLe2QGeneric(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.normalizeAssumingLe2QGeneric()
	}
}

func BenchmarkExceedsGeneric(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.exceedsGeneric(uint32(10))
	}
}

func BenchmarkDecomposeGeneric(b *testing.B) {
	var p, p0, p1 Poly
	for i := 0; i < b.N; i++ {
		p.decomposeGeneric(&p0, &p1)
	}
}

func BenchmarkMakeHintGeneric(b *testing.B) {
	var p, p0, p1 Poly
	for i := 0; i < b.N; i++ {
		p.makeHintGeneric(&p0, &p1)
	}
}

func BenchmarkMulBy2toDGeneric(b *testing.B) {
	var p, q Poly
	for i := 0; i < b.N; i++ {
		p.mulBy2toDGeneric(&q)
	}
}

func BenchmarkMulHat(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.MulHat(&p, &p)
	}
}

func BenchmarkAdd(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.Add(&p, &p)
	}
}

func BenchmarkSub(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.Sub(&p, &p)
	}
}

func BenchmarkReduceLe2Q(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.ReduceLe2Q()
	}
}

func BenchmarkNormalize(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.Normalize()
	}
}

func BenchmarkNormalizeAssumingLe2Q(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.NormalizeAssumingLe2Q()
	}
}

func BenchmarkExceeds(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.Exceeds(uint32(10))
	}
}

func BenchmarkDecompose(b *testing.B) {
	var p, p0, p1 Poly
	for i := 0; i < b.N; i++ {
		p.Decompose(&p0, &p1)
	}
}

func BenchmarkMakeHint(b *testing.B) {
	var p, p0, p1 Poly
	for i := 0; i < b.N; i++ {
		p.MakeHint(&p0, &p1)
	}
}

func BenchmarkMulBy2toD(b *testing.B) {
	var p, q Poly
	for i := 0; i < b.N; i++ {
		p.MulBy2toD(&q)
	}
}
