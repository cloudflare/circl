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
