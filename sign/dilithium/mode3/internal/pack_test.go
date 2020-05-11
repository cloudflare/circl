package internal

import (
	"testing"

	common "github.com/cloudflare/circl/sign/dilithium/internal"
)

func TestPolyPackLeqEta(t *testing.T) {
	var p1, p2 common.Poly
	var seed [32]byte
	var buf [PolyLeqEtaSize]byte

	for i := uint16(0); i < 100; i++ {
		// Note that DeriveUniformLeqEta sets p to the right kind of
		// unnormalized vector.
		PolyDeriveUniformLeqEta(&p1, &seed, i)
		for j := 0; j < PolyLeqEtaSize; j++ {
			if p1[j] < common.Q-Eta || p1[j] > common.Q+Eta {
				t.Fatalf("DerveUniformLeqEta out of bounds")
			}
		}
		PolyPackLeqEta(&p1, buf[:])
		PolyUnpackLeqEta(&p2, buf[:])
		if p1 != p2 {
			t.Fatalf("%v != %v", p1, p2)
		}
	}
}

func TestPolyPackT1(t *testing.T) {
	var p1, p2 common.Poly
	var seed [32]byte
	var buf [common.PolyT1Size]byte

	for i := uint16(0); i < 100; i++ {
		PolyDeriveUniform(&p1, &seed, i)
		p1.Normalize()
		for j := 0; j < common.N; j++ {
			p1[j] &= 0x1ff
		}
		p1.PackT1(buf[:])
		p2.UnpackT1(buf[:])
		if p1 != p2 {
			t.Fatalf("%v != %v", p1, p2)
		}
	}
}

func TestPolyPackT0(t *testing.T) {
	var p, p0, p1, p2 common.Poly
	var seed [32]byte
	var buf [common.PolyT0Size]byte

	for i := uint16(0); i < 100; i++ {
		PolyDeriveUniform(&p, &seed, i)
		p.Normalize()
		p.Power2Round(&p0, &p1)

		p0.PackT0(buf[:])
		p2.UnpackT0(buf[:])
		if p0 != p2 {
			t.Fatalf("%v != %v", p1, p2)
		}
	}
}

func TestPolyPackLeGamma1(t *testing.T) {
	var p0, p1 common.Poly
	var seed [48]byte
	var buf [common.PolyLeGamma1Size]byte

	for i := uint16(0); i < 100; i++ {
		PolyDeriveUniformLeGamma1(&p0, &seed, i)
		p0.Normalize()

		p0.PackLeGamma1(buf[:])
		p1.UnpackLeGamma1(buf[:])
		if p0 != p1 {
			t.Fatalf("%v != %v", p0, p1)
		}
	}
}
