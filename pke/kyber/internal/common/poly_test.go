package common

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func (p *Poly) RandAbsLe9Q() {
	max := 9 * uint32(Q)
	r := randSliceUint32WithMax(uint(N), max)
	for i := 0; i < N; i++ {
		p[i] = int16(int32(r[i]))
	}
}

// Returns x mod^± q
func sModQ(x int16) int16 {
	x = x % Q
	if x >= (Q-1)/2 {
		x = x - Q
	}
	return x
}

func TestDecompressMessage(t *testing.T) {
	var m, m2 [PlaintextSize]byte
	var p Poly
	for i := 0; i < 1000; i++ {
		if n, err := rand.Read(m[:]); err != nil {
			t.Error(err)
		} else if n != len(m) {
			t.Fatal("short read from RNG")
		}

		p.DecompressMessage(m[:])
		p.CompressMessageTo(m2[:])
		if m != m2 {
			t.Fatal()
		}
	}
}

func TestCompress(t *testing.T) {
	for _, d := range []int{4, 5, 10, 11} {
		d := d
		t.Run(fmt.Sprintf("d=%d", d), func(t *testing.T) {
			var p, q Poly
			bound := (Q + (1 << uint(d))) >> uint(d+1)
			buf := make([]byte, (N*d-1)/8+1)
			for i := 0; i < 1000; i++ {
				p.Rand()
				p.CompressTo(buf, d)
				q.Decompress(buf, d)
				for j := 0; j < N; j++ {
					diff := sModQ(p[j] - q[j])
					if diff < 0 {
						diff = -diff
					}
					if diff > bound {
						t.Logf("%v\n", buf)
						t.Fatalf("|%d - %d mod^± q| = %d > %d, j=%d",
							p[i], q[j], diff, bound, j)
					}
				}
			}
		})
	}
}

func TestCompressMessage(t *testing.T) {
	var p Poly
	var m [32]byte
	ok := true
	for i := 0; i < int(Q); i++ {
		p[0] = int16(i)
		p.CompressMessageTo(m[:])
		want := byte(0)
		if i >= 833 && i < 2497 {
			want = 1
		}
		if m[0] != want {
			ok = false
			t.Logf("%d %d %d", i, want, m[0])
		}
	}
	if !ok {
		t.Fatal()
	}
}

func TestMulHat(t *testing.T) {
	for k := 0; k < 1000; k++ {
		var a, b, p, ah, bh, ph Poly
		a.RandAbsLeQ()
		b.RandAbsLeQ()
		b[0] = 1

		ah = a
		bh = b
		ah.NTT()
		bh.NTT()
		ph.MulHat(&ah, &bh)
		ph.BarrettReduce()
		ph.InvNTT()

		for i := 0; i < N; i++ {
			for j := 0; j < N; j++ {
				v := montReduce(int32(a[i]) * int32(b[j]))
				k := i + j
				if k >= N {
					// Recall xᴺ = -1.
					k -= N
					v = -v
				}
				p[k] = barrettReduce(v + p[k])
			}
		}

		for i := 0; i < N; i++ {
			p[i] = int16((int32(p[i]) * ((1 << 16) % int32(Q))) % int32(Q))
		}

		p.Normalize()
		ph.Normalize()
		a.Normalize()
		b.Normalize()

		if p != ph {
			t.Fatalf("%v\n%v\n%v\n%v", a, b, p, ph)
		}
	}
}

func TestAddAgainstGeneric(t *testing.T) {
	for k := 0; k < 1000; k++ {
		var p1, p2, a, b Poly
		a.RandAbsLeQ()
		b.RandAbsLeQ()
		p1.Add(&a, &b)
		p2.addGeneric(&a, &b)
		if p1 != p2 {
			t.Fatalf("Add(%v, %v) = \n%v \n!= %v", a, b, p1, p2)
		}
	}
}

func BenchmarkAdd(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.Add(&p, &p)
	}
}

func BenchmarkAddGeneric(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.addGeneric(&p, &p)
	}
}

func TestSubAgainstGeneric(t *testing.T) {
	for k := 0; k < 1000; k++ {
		var p1, p2, a, b Poly
		a.RandAbsLeQ()
		b.RandAbsLeQ()
		p1.Sub(&a, &b)
		p2.subGeneric(&a, &b)
		if p1 != p2 {
			t.Fatalf("Sub(%v, %v) = \n%v \n!= %v", a, b, p1, p2)
		}
	}
}

func BenchmarkSub(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.Sub(&p, &p)
	}
}

func BenchmarkSubGeneric(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.subGeneric(&p, &p)
	}
}

func TestMulHatAgainstGeneric(t *testing.T) {
	for k := 0; k < 1000; k++ {
		var p1, p2, a, b Poly
		a.RandAbsLeQ()
		b.RandAbsLeQ()
		a2 := a
		b2 := b
		a2.Tangle()
		b2.Tangle()
		p1.MulHat(&a2, &b2)
		p1.Detangle()
		p2.mulHatGeneric(&a, &b)
		if p1 != p2 {
			t.Fatalf("MulHat(%v, %v) = \n%v \n!= %v", a, b, p1, p2)
		}
	}
}

func BenchmarkMulHat(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.MulHat(&p, &p)
	}
}

func BenchmarkMulHatGeneric(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.mulHatGeneric(&p, &p)
	}
}

func BenchmarkBarrettReduce(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.BarrettReduce()
	}
}

func BenchmarkBarrettReduceGeneric(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.barrettReduceGeneric()
	}
}

func TestBarrettReduceAgainstGeneric(t *testing.T) {
	for k := 0; k < 1000; k++ {
		var p1, p2, a Poly
		a.RandAbsLe9Q()
		p1 = a
		p2 = a
		p1.BarrettReduce()
		p2.barrettReduceGeneric()
		if p1 != p2 {
			t.Fatalf("BarrettReduce(%v) = \n%v \n!= %v", a, p1, p2)
		}
	}
}

func BenchmarkNormalize(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.Normalize()
	}
}

func BenchmarkNormalizeGeneric(b *testing.B) {
	var p Poly
	for i := 0; i < b.N; i++ {
		p.barrettReduceGeneric()
	}
}

func TestNormalizeAgainstGeneric(t *testing.T) {
	for k := 0; k < 1000; k++ {
		var p1, p2, a Poly
		a.RandAbsLe9Q()
		p1 = a
		p2 = a
		p1.Normalize()
		p2.normalizeGeneric()
		if p1 != p2 {
			t.Fatalf("Normalize(%v) = \n%v \n!= %v", a, p1, p2)
		}
	}
}

func (p *Poly) OldCompressTo(m []byte, d int) {
	switch d {
	case 4:
		var t [8]uint16
		idx := 0
		for i := 0; i < N/8; i++ {
			for j := 0; j < 8; j++ {
				t[j] = uint16(((uint32(p[8*i+j])<<4)+uint32(Q)/2)/
					uint32(Q)) & ((1 << 4) - 1)
			}
			m[idx] = byte(t[0]) | byte(t[1]<<4)
			m[idx+1] = byte(t[2]) | byte(t[3]<<4)
			m[idx+2] = byte(t[4]) | byte(t[5]<<4)
			m[idx+3] = byte(t[6]) | byte(t[7]<<4)
			idx += 4
		}

	case 5:
		var t [8]uint16
		idx := 0
		for i := 0; i < N/8; i++ {
			for j := 0; j < 8; j++ {
				t[j] = uint16(((uint32(p[8*i+j])<<5)+uint32(Q)/2)/
					uint32(Q)) & ((1 << 5) - 1)
			}
			m[idx] = byte(t[0]) | byte(t[1]<<5)
			m[idx+1] = byte(t[1]>>3) | byte(t[2]<<2) | byte(t[3]<<7)
			m[idx+2] = byte(t[3]>>1) | byte(t[4]<<4)
			m[idx+3] = byte(t[4]>>4) | byte(t[5]<<1) | byte(t[6]<<6)
			m[idx+4] = byte(t[6]>>2) | byte(t[7]<<3)
			idx += 5
		}

	case 10:
		var t [4]uint16
		idx := 0
		for i := 0; i < N/4; i++ {
			for j := 0; j < 4; j++ {
				t[j] = uint16(((uint32(p[4*i+j])<<10)+uint32(Q)/2)/
					uint32(Q)) & ((1 << 10) - 1)
			}
			m[idx] = byte(t[0])
			m[idx+1] = byte(t[0]>>8) | byte(t[1]<<2)
			m[idx+2] = byte(t[1]>>6) | byte(t[2]<<4)
			m[idx+3] = byte(t[2]>>4) | byte(t[3]<<6)
			m[idx+4] = byte(t[3] >> 2)
			idx += 5
		}
	case 11:
		var t [8]uint16
		idx := 0
		for i := 0; i < N/8; i++ {
			for j := 0; j < 8; j++ {
				t[j] = uint16(((uint32(p[8*i+j])<<11)+uint32(Q)/2)/
					uint32(Q)) & ((1 << 11) - 1)
			}
			m[idx] = byte(t[0])
			m[idx+1] = byte(t[0]>>8) | byte(t[1]<<3)
			m[idx+2] = byte(t[1]>>5) | byte(t[2]<<6)
			m[idx+3] = byte(t[2] >> 2)
			m[idx+4] = byte(t[2]>>10) | byte(t[3]<<1)
			m[idx+5] = byte(t[3]>>7) | byte(t[4]<<4)
			m[idx+6] = byte(t[4]>>4) | byte(t[5]<<7)
			m[idx+7] = byte(t[5] >> 1)
			m[idx+8] = byte(t[5]>>9) | byte(t[6]<<2)
			m[idx+9] = byte(t[6]>>6) | byte(t[7]<<5)
			m[idx+10] = byte(t[7] >> 3)
			idx += 11
		}
	default:
		panic("unsupported d")
	}
}

func TestCompressFullInputFirstCoeff(t *testing.T) {
	for _, d := range []int{4, 5, 10, 11} {
		d := d
		t.Run(fmt.Sprintf("d=%d", d), func(t *testing.T) {
			var p, q Poly
			bound := (Q + (1 << uint(d))) >> uint(d+1)
			buf := make([]byte, (N*d-1)/8+1)
			buf2 := make([]byte, len(buf))
			for i := int16(0); i < Q; i++ {
				p[0] = i
				p.CompressTo(buf, d)
				p.OldCompressTo(buf2, d)
				if !bytes.Equal(buf, buf2) {
					t.Fatalf("%d", i)
				}
				q.Decompress(buf, d)
				diff := sModQ(p[0] - q[0])
				if diff < 0 {
					diff = -diff
				}
				if diff > bound {
					t.Logf("%v\n", buf)
					t.Fatalf("|%d - %d mod^± q| = %d > %d",
						p[0], q[0], diff, bound)
				}
			}
		})
	}
}
