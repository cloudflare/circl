package internal

import (
	"flag"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/internal/common"
)

var runVeryLongTest = flag.Bool("very-long", false, "runs very long tests")

func TestDecompose(t *testing.T) {
	for a := uint32(0); a < common.Q; a++ {
		a0PlusQ, a1 := decompose(a)
		a0 := int32(a0PlusQ) - int32(common.Q)
		recombined := a0 + int32(Alpha*a1)
		if a1 == 0 && recombined < 0 {
			recombined += common.Q
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
	for w := uint32(0); w < common.Q; w++ {
		w0, w1 := decompose(w)
		for fn := uint32(0); fn <= Gamma2; fn++ {
			fsign := false
			for {
				var f uint32
				if fsign {
					if fn == 0 {
						break
					}
					f = common.Q - fn
				} else {
					f = fn
				}

				hint := makeHint(common.ReduceLe2Q(w0+common.Q-f), w1)
				w1p := useHint(common.ReduceLe2Q(w+common.Q-f), hint)
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

func BenchmarkDecompose(b *testing.B) {
	var p, p0, p1 common.Poly
	for i := 0; i < b.N; i++ {
		PolyDecompose(&p, &p0, &p1)
	}
}

func BenchmarkMakeHint(b *testing.B) {
	var p, p0, p1 common.Poly
	for i := 0; i < b.N; i++ {
		PolyMakeHint(&p, &p0, &p1)
	}
}
