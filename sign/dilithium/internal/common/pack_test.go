package common

import (
	"math/rand"
	"testing"
)

func TestPackLe16AgainstGeneric(t *testing.T) {
	var p Poly
	var buf1, buf2 [PolyLe16Size]byte
	for j := 0; j < 1000; j++ {
		for i := 0; i < 256; i++ {
			p[i] = uint32(rand.Intn(16))
		}
		p.PackLe16(buf1[:])
		p.packLe16Generic(buf2[:])
		if buf1 != buf2 {
			t.Fatal()
		}
	}
}

func BenchmarkPackLe16(b *testing.B) {
	var p Poly
	var buf [PolyLe16Size]byte
	for i := 0; i < b.N; i++ {
		p.PackLe16(buf[:])
	}
}

func BenchmarkPackLe16Generic(b *testing.B) {
	var p Poly
	var buf [PolyLe16Size]byte
	for i := 0; i < b.N; i++ {
		p.packLe16Generic(buf[:])
	}
}

func BenchmarkUnpackLeGamma1(b *testing.B) {
	var p Poly
	var buf [PolyLeGamma1Size]byte
	for i := 0; i < b.N; i++ {
		p.UnpackLeGamma1(buf[:])
	}
}
