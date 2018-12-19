// +build amd64

package ecdhx_test

import (
	"fmt"
	"testing"

	dh "github.com/cloudflare/circl/ecdhx"
)

func TestX25519Base(t *testing.T) {
	const times = 128
	var got, want dh.Key255
	base := dh.GetBase255()
	for j := 0; j < times; j++ {
		input := dh.RandomKey255()
		x, y := input, input
		for i := 0; i < times; i++ {
			want, got = x.Shared(base), y.KeyGen()
			x, y = want, got
		}
		if got != want {
			t.Errorf("[incorrect result]\ninput: %v\ngot:   %v\nwant:  %v\n", input, got, want)
		}
	}
}

func TestX448Base(t *testing.T) {
	const times = 128
	var got, want dh.Key448
	base := dh.GetBase448()
	for j := 0; j < times; j++ {
		input := dh.RandomKey448()
		x, y := input, input
		for i := 0; i < times; i++ {
			want, got = x.Shared(base), y.KeyGen()
			x, y = want, got
		}
		if got != want {
			t.Errorf("[incorrect result]\ninput: %v\ngot:   %v\nwant:  %v\n", input, got, want)
		}
	}
}

func BenchmarkX25519(b *testing.B) {
	key := dh.RandomKey255()
	in := dh.RandomKey255()
	b.SetBytes(dh.SizeKey255)
	b.Run("Random", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			dh.RandomKey255()
		}
	})
	b.Run("KeyGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out := in.KeyGen()
			in = out
		}
	})
	b.Run("Shared", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out := key.Shared(in)
			in = key
			key = out
		}
	})
}

func BenchmarkX448(b *testing.B) {
	key := dh.RandomKey448()
	in := dh.RandomKey448()
	b.SetBytes(dh.SizeKey448)
	b.Run("Random", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			dh.RandomKey448()
		}
	})
	b.Run("KeyGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out := in.KeyGen()
			in = out
		}
	})
	b.Run("Shared", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out := key.Shared(in)
			in = key
			key = out
		}
	})
}

func Example_x25519() {
	// Generating Alice's secret and public keys
	aliceSecret := dh.RandomKey255()
	alicePublic := aliceSecret.KeyGen()
	// Generating Bob's secret and public keys
	bobSecret := dh.RandomKey255()
	bobPublic := bobSecret.KeyGen()
	// Deriving Alice's shared key
	aliceShared := aliceSecret.Shared(bobPublic)
	// Deriving Bob's shared key
	bobShared := bobSecret.Shared(alicePublic)

	fmt.Println(aliceShared == bobShared)
	// Output: true
}
