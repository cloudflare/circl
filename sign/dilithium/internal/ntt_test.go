package internal

import (
	"math/rand"
	"testing"
)

func (p *Poly) RandLe2Q() {
	for i := uint(0); i < N; i++ {
		p[i] = uint32(rand.Intn(int(2 * Q)))
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

func TestNTTAgainstGeneric(t *testing.T) {
	for k := 0; k < 1000; k++ {
		var p Poly
		p.RandLe2Q()
		q1 := p
		q2 := p
		q1.NTT()
		q2.nttGeneric()
		if q1 != q2 {
			t.Fatalf("NTT(%v) = %v != %v", p, q1, q2)
		}
	}
}

func TestNTT(t *testing.T) {
	for k := 0; k < 1000; k++ {
		var p, q Poly
		p.RandLe2Q()
		q = p
		q.Normalize()
		p.NTT()
		for i := uint(0); i < N; i++ {
			if p[i] > 18*Q {
				t.Fatalf("NTT(%v)[%d] = %d > 18*Q", q, i, p[i])
			}
		}
		p.ReduceLe2Q()
		p.InvNTT()
		for i := uint(0); i < N; i++ {
			if p[i] > 2*Q {
				t.Fatalf("InvNTT(%v)[%d] > 2*Q", q, i)
			}
		}
		p.Normalize()
		for i := uint(0); i < N; i++ {
			if p[i] != uint32((uint64(q[i])*uint64(1<<32))%Q) {
				t.Fatalf("%v != %v", p, q)
			}
		}
	}
}

func BenchmarkGenericNTT(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.nttGeneric()
	}
}

func BenchmarkGenericInvNTT(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.invNttGeneric()
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

func BenchmarkMulHat(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.MulHat(&p, &p)
	}
}

func BenchmarkNTT(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.NTT()
	}
}

func BenchmarkInvNTT(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.InvNTT()
	}
}

func BenchmarkAdd(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.Add(&p, &p)
	}
}
