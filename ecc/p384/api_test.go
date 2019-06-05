// +build arm64 amd64

package p384_test

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/ecc/p384"
)

func BenchmarkScalarMult(b *testing.B) {
	curve := p384.P384()
	params := curve.Params()
	K, _ := rand.Int(rand.Reader, params.N)
	M, _ := rand.Int(rand.Reader, params.N)
	N, _ := rand.Int(rand.Reader, params.N)
	k := K.Bytes()
	m := M.Bytes()
	n := N.Bytes()

	b.Run("kG", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			curve.ScalarBaseMult(k)
		}
	})
	b.Run("kP", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			curve.ScalarMult(params.Gx, params.Gy, k)
		}
	})
	b.Run("kG+lP", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = curve.SimultaneousMult(params.Gx, params.Gy, m, n)
		}
	})

	curveStd := elliptic.P384()
	prefix := "elliptic"

	b.Run(fmt.Sprintf("%v/kG", prefix), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			curveStd.ScalarBaseMult(k)
		}
	})
	b.Run(fmt.Sprintf("%v/kP", prefix), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			curveStd.ScalarMult(params.Gx, params.Gy, k)
		}
	})
}

func ExampleP384() {
	// import "github.com/cloudflare/circl/ecc/p384"
	// import "crypto/elliptic"
	circl := p384.P384()
	stdlib := elliptic.P384()

	params := circl.Params()
	K, _ := rand.Int(rand.Reader, params.N)
	k := K.Bytes()

	x1, y1 := circl.ScalarBaseMult(k)
	x2, y2 := stdlib.ScalarBaseMult(k)
	fmt.Printf("%v, %v", x1.Cmp(x2) == 0, y1.Cmp(y2) == 0)
	// Output: true, true
}
