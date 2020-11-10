package common

import (
	"flag"
	mathRand "math/rand"
	"testing"
)

var runVeryLongTest = flag.Bool("very-long", false, "runs very long tests")

func modQ32(x int32) int16 {
	y := int16(x % int32(Q))
	if y < 0 {
		y += Q
	}
	return y
}

func TestBarrettReduceFull(t *testing.T) {
	if !*runVeryLongTest {
		t.SkipNow()
	}
	for x := -1 << 15; x <= 1<<15; x++ {
		y1 := barrettReduce(int16(x))
		y2 := int16(x) % Q
		if y2 < 0 {
			y2 += Q
		}
		if x < 0 && int16(-x)%Q == 0 {
			y1 -= Q
		}
		if y1 != y2 {
			t.Fatalf("%d %d %d", x, y1, y2)
		}
	}
}

func TestMontReduce(t *testing.T) {
	for i := 0; i < 1000; i++ {
		x := mathRand.Int31n(int32(Q)*(1<<16)) - int32(Q)*(1<<15)
		y := montReduce(x)
		if modQ32(x) != modQ32(int32(y)*(1<<16)) {
			t.Fatalf("%d", x)
		}
	}
}

func TestToMontFull(t *testing.T) {
	if !*runVeryLongTest {
		t.SkipNow()
	}
	for x := -(1 << 15); x < 1<<15; x++ {
		y := toMont(int16(x))
		if modQ32(int32(y)) != modQ32(int32(x*2285)) {
			t.Fatalf("%d", x)
		}
	}
}

func TestMontReduceFull(t *testing.T) {
	if !*runVeryLongTest {
		t.SkipNow()
	}
	for x := -int32(Q) * (1 << 15); x <= int32(Q)*(1<<15); x++ {
		y := montReduce(x)
		if modQ32(x) != modQ32(int32(y)*(1<<16)) {
			t.Fatalf("%d", x)
		}
	}
}

func TestCSubQFull(t *testing.T) {
	if !*runVeryLongTest {
		t.SkipNow()
	}
	for x := -29439; x < 1<<15; x++ {
		y1 := csubq(int16(x))
		y2 := x
		if int16(x) >= Q {
			y2 -= int(Q)
		}
		if y1 != int16(y2) {
			t.Fatalf("%d", x)
		}
	}
}
