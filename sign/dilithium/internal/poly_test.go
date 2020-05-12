package internal

import (
	"math/rand"
	"testing"
)

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
		for j := 0; j < 256; j++ {
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

func BenchmarkGenericMulHat(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.mulHatGeneric(&p, &p)
	}
}

func BenchmarkGenericAdd(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.addGeneric(&p, &p)
	}
}

func BenchmarkGenericSub(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.subGeneric(&p, &p)
	}
}

func BenchmarkGenericReduceLe2Q(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.reduceLe2QGeneric()
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
