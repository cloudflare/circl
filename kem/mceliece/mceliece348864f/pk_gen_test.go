package mceliece348864f

import (
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func TestCtz(t *testing.T) {
	expected := []int{
		64, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2,
		0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0,
		1, 0, 2, 0, 1, 0, 6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1,
		0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0,
		2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 7, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
		0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0,
		1, 0, 4, 0, 1, 0,
	}
	for i := uint64(0); i < 100; i++ {
		got := ctz(i)
		if got != expected[i] {
			test.ReportError(t, got, expected[i])
		}
	}
}

func TestSameMask(t *testing.T) {
	expected := []uint64{
		0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0, 0,
		0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0, 0,
		0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0, 0,
		0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0, 0,
		0xFFFFFFFFFFFFFFFF,
	}
	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			got := sameMask64(uint16(i), uint16(j))
			want := expected[i*5+j]
			if got != want {
				test.ReportError(t, got, want)
			}
		}
	}
}
