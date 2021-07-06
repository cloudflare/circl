package common

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"math"
	"testing"
)

var runVeryLongTest = flag.Bool("very-long", false, "runs very long tests")

func randSliceUint32(length uint) []uint32 { return randSliceUint32WithMax(length, math.MaxUint32) }

func randSliceUint32WithMax(length uint, max uint32) []uint32 {
	bytes := make([]uint8, 4*length)
	if n, err := rand.Read(bytes); err != nil {
		panic(err)
	} else if n < len(bytes) {
		panic("short read from RNG")
	}
	x := make([]uint32, length)
	for i := range x {
		x[i] = binary.LittleEndian.Uint32(bytes[4*i:]) % max
	}
	return x
}

func TestModQ(t *testing.T) {
	const testTimes = 1000
	r := randSliceUint32(testTimes)
	for i := 0; i < testTimes; i++ {
		x := r[i]
		y := modQ(x)
		if y > Q {
			t.Fatalf("modQ(%d) > Q", x)
		}
		if y != x%Q {
			t.Fatalf("modQ(%d) != %d (mod Q)", x, x)
		}
	}
}

func TestReduceLe2Q(t *testing.T) {
	const testTimes = 1000
	r := randSliceUint32(testTimes)
	for i := 0; i < testTimes; i++ {
		x := r[i]
		y := reduceLe2Q(x)
		if y > 2*Q {
			t.Fatalf("reduce_le2q(%d) > 2Q", x)
		}
		if y%Q != x%Q {
			t.Fatalf("reduce_le2q(%d) != %d (mod Q)", x, x)
		}
	}
}

func TestPower2Round(t *testing.T) {
	for a := uint32(0); a < Q; a++ {
		a0PlusQ, a1 := power2round(a)
		a0 := int32(a0PlusQ) - int32(Q)
		if int32(a) != a0+int32((1<<D)*a1) {
			t.Fatalf("power2round(%v) doesn't recombine", a)
		}
		if (-(1 << (D - 1)) >= a0) || (a0 > 1<<(D-1)) {
			t.Fatalf("power2round(%v): a0 out of bounds", a)
		}
		if a1 > (1 << (23 - 14)) { // 23 ~ 2log Q.
			t.Fatalf("power2round(%v): a1 out of bounds", a)
		}
	}
}

func TestDecompose(t *testing.T) {
	for a := uint32(0); a < Q; a++ {
		a0PlusQ, a1 := decompose(a)
		a0 := int32(a0PlusQ) - int32(Q)
		recombined := a0 + int32(Alpha*a1)
		if a1 == 0 && recombined < 0 {
			recombined += Q
			if -(Alpha/2) > a0 || a0 >= 0 {
				t.Fatalf("decompose(%v): a0 out of bounds", a)
			}
		} else {
			if (-(Alpha / 2) >= a0) || (a0 > Alpha/2) {
				t.Fatalf("decompose(%v): a0 out of bounds", a)
			}
		}
		if int32(a) != recombined {
			t.Fatalf("decompose(%v) doesn't recombine %v %v", a, a0, a1)
		}
	}
}

func TestMakeHint(t *testing.T) {
	if !*runVeryLongTest {
		t.SkipNow()
	}
	for w := uint32(0); w < Q; w++ {
		w0, w1 := decompose(w)
		for fn := uint32(0); fn <= Gamma2; fn++ {
			fsign := false
			for {
				var f uint32
				if fsign {
					if fn == 0 {
						break
					}
					f = Q - fn
				} else {
					f = fn
				}

				hint := makeHint(reduceLe2Q(w0+Q-f), w1)
				w1p := useHint(reduceLe2Q(w+Q-f), hint)
				if w1p != w1 {
					t.Fatal()
				}

				if fsign {
					break
				}
				fsign = true
			}
		}
	}
}
