package goldilocks

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/conv"
)

func TestDevel(t *testing.T) {
	var e Curve
	var k [ScalarSize]byte
	rand.Read(k[:])
	k[0] = 1
	t.Logf("\nk: %v\n", conv.BytesLe2Hex(k[:]))
	P := e.ScalarBaseMult(k[:])
	P.ToAffine()
	t.Logf("\n%v\n", P)

}

func BenchmarkTwistPoint(b *testing.B) {
	e := &twistCurve{}
	P := e.Identity()
	Q := &pointR2{}

	b.Run("mul", func(b *testing.B) {
		var scalar [ScalarSize]byte
		for i := range scalar {
			scalar[i] = 0xFF
		}
		for i := 0; i < b.N; i++ {
			e.ScalarBaseMult(scalar[:])
		}
	})
	b.Run("double", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.Double()
		}
	})
	b.Run("add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.add(Q)
		}
	})
}
