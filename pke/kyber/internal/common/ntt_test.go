package common

import (
	"math/rand"
	"testing"
)

func BenchmarkNTT(b *testing.B) {
	var a Poly
	for i := 0; i < b.N; i++ {
		a.NTT()
	}
}

func BenchmarkNTTGeneric(b *testing.B) {
	var a Poly
	for i := 0; i < b.N; i++ {
		a.nttGeneric()
	}
}

func BenchmarkInvNTT(b *testing.B) {
	var a Poly
	for i := 0; i < b.N; i++ {
		a.InvNTT()
	}
}

func (p *Poly) Rand() {
	for i := 0; i < N; i++ {
		p[i] = int16(rand.Intn(int(Q))) // nolint:gosec
	}
}

func (p *Poly) RandAbsLeQ() {
	for i := 0; i < N; i++ {
		p[i] = int16(rand.Intn(int(2*Q))) - Q // nolint:gosec
	}
}

func TestNTTAgainstGeneric(t *testing.T) {
	for k := 0; k < 1000; k++ {
		var p, q1, q2 Poly
		p.RandAbsLeQ()
		q1 = p
		q2 = p
		q1.NTT()
		q2.nttGeneric()
		if q1 != q2 {
			t.Fatalf("NTT(%v) = \n%v \n!= %v", p, q2, q1)
		}
	}
}

func TestNTT(t *testing.T) {
	for k := 0; k < 1000; k++ {
		var p, q Poly
		p.RandAbsLeQ()
		q = p
		q.Normalize()
		p.NTT()
		for i := 0; i < N; i++ {
			if p[i] > 7*Q || 7*Q < p[i] {
				t.Fatal()
			}
		}
		p.Normalize()
		p.InvNTT()
		for i := 0; i < N; i++ {
			if p[i] > Q || p[i] < -Q {
				t.Fatal()
			}
		}
		p.Normalize()
		for i := 0; i < N; i++ {
			if int32(p[i]) != (int32(q[i])*(1<<16))%int32(Q) {
				t.Fatal()
			}
		}
	}
}
