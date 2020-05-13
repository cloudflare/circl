package f1600x4

import (
	"testing"
)

func TestF1600x4(t *testing.T) {
	if !Available {
		t.Skip()
	}
	var state State
	a := state.Initialize()

	expected := []uint64{
		0xF1258F7940E1DDE7, 0x84D5CCF933C0478A, 0xD598261EA65AA9EE,
		0xBD1547306F80494D, 0x8B284E056253D057, 0xFF97A42D7F8E6FD4,
		0x90FEE5A0A44647C4, 0x8C5BDA0CD6192E76, 0xAD30A6F71B19059C,
		0x30935AB7D08FFC64, 0xEB5AA93F2317D635, 0xA9A6E6260D712103,
		0x81A57C16DBCF555F, 0x43B831CD0347C826, 0x01F22F1A11A5569F,
		0x05E5635A21D9AE61, 0x64BEFEF28CC970F2, 0x613670957BC46611,
		0xB87C5A554FD00ECB, 0x8C3EE88A1CCF32C8, 0x940C7922AE3A2614,
		0x1841F924A2C509E4, 0x16F53526E70465C2, 0x75F644E97F30A13B,
		0xEAF1FF7B5CECA249,
	}

	state.Permute()

	for i := 0; i < 25; i++ {
		if a[4*i] != expected[i] {
			t.Fatal()
		}
	}
}

func BenchmarkF1600x4(b *testing.B) {
	if !Available {
		b.Skip()
	}
	var state State
	_ = state.Initialize()

	for i := 0; i < b.N; i++ {
		state.Permute()
	}
}
