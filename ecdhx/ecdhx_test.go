// +build amd64

package ecdhx_test

import (
	"fmt"
	"testing"

	dh "github.com/cloudflare/circl/ecdhx"
)

func baseTest(t *testing.T, x, base dh.XKey) {
	const times = 1 << 10
	y := x
	for i := 0; i < times; i++ {
		want, got := x.Shared(base), y.KeyGen()
		x, y = want, got
		if got != want {
			t.Errorf("[incorrect result]\ninput: %v\ngot:   %v\nwant:  %v\n", x, got, want)
		}
	}
}

func TestBase(t *testing.T) {
	t.Run("X25519", func(t *testing.T) { baseTest(t, dh.RandomKey255(), dh.GetBase255()) })
	t.Run("X448", func(t *testing.T) { baseTest(t, dh.RandomKey448(), dh.GetBase448()) })
}

func ecdhx(b *testing.B, x, y dh.XKey) {
	b.SetBytes(int64(x.Size()))
	b.Run("KeyGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x = x.KeyGen()
		}
	})
	b.Run("Shared", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z := x.Shared(y)
			y = x
			x = z
		}
	})
}

func BenchmarkECDHX(b *testing.B) {
	b.Run("X25519", func(b *testing.B) { ecdhx(b, dh.RandomKey255(), dh.RandomKey255()) })
	b.Run("X448", func(b *testing.B) { ecdhx(b, dh.RandomKey448(), dh.RandomKey448()) })
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
