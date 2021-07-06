package common

import "testing"

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

func BenchmarkInvNTTGeneric(b *testing.B) {
	var a Poly
	for i := 0; i < b.N; i++ {
		a.invNTTGeneric()
	}
}

func (p *Poly) Rand() {
	max := uint32(Q)
	r := randSliceUint32WithMax(uint(N), max)
	for i := 0; i < N; i++ {
		p[i] = int16(r[i])
	}
}

func (p *Poly) RandAbsLeQ() {
	max := 2 * uint32(Q)
	r := randSliceUint32WithMax(uint(N), max)
	for i := 0; i < N; i++ {
		p[i] = int16(int32(r[i]) - int32(Q))
	}
}

func TestNTTAgainstGeneric(t *testing.T) {
	for k := 0; k < 1000; k++ {
		var p, q1, q2 Poly
		p.RandAbsLeQ()
		q1 = p
		q2 = p
		q1.NTT()
		q1.Detangle()
		q2.nttGeneric()
		if q1 != q2 {
			t.Fatalf("NTT(%v) = \n%v \n!= %v", p, q2, q1)
		}
	}
}

func TestInvNTTAgainstGeneric(t *testing.T) {
	for k := 0; k < 1000; k++ {
		var p, q1, q2 Poly
		p.RandAbsLeQ()
		q1 = p
		q2 = p
		q1.Tangle()
		q1.InvNTT()
		q2.invNTTGeneric()

		q1.Normalize()
		q2.Normalize()

		if q1 != q2 {
			t.Fatalf("InvNTT(%v) = \n%v \n!= %v", p, q2, q1)
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

func TestInvNTTReductions(t *testing.T) {
	// Simulates bounds on coefficients in InvNTT.

	xs := [256]int{}
	for i := 0; i < 256; i++ {
		xs[i] = 1
	}

	r := -1
	for layer := 1; layer < 8; layer++ {
		w := 1 << uint(layer)
		i := 0
		for i+w < 256 {
			xs[i] = xs[i] + xs[i+w]
			if xs[i] > 9 {
				t.Fatal()
			}
			xs[i+w] = 1
			i++
			if i%w == 0 {
				i += w
			}
		}
		for {
			r++
			i := InvNTTReductions[r]
			if i < 0 {
				break
			}
			xs[i] = 1
		}
	}
}
