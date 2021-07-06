package common

import "testing"

func (p *Poly) RandLe2Q() {
	max := 2 * uint32(Q)
	r := randSliceUint32WithMax(N, max)
	copy(p[:], r)
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

func BenchmarkNTTGeneric(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.nttGeneric()
	}
}

func BenchmarkInvNTTGeneric(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.invNttGeneric()
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
