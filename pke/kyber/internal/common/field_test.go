package common

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
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

func randSliceUint32WithMax(length uint, max uint32) []uint32 {
	bytes := make([]uint8, 4*length)
	n, err := rand.Read(bytes)
	if err != nil {
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

func TestMontReduce(t *testing.T) {
	size := 1000
	max := uint32(Q) * (1 << 16)
	mid := int32(Q) * (1 << 15)
	r := randSliceUint32WithMax(uint(size), max)

	for i := 0; i < size; i++ {
		x := int32(r[i]) - mid
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
