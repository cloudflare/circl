package curve4q

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/cloudflare/circl/ecc/fourq"
	"github.com/cloudflare/circl/internal/test"
)

func TestDH(t *testing.T) {
	var secretAlice, publicAlice, sharedAlice Key
	var secretBob, publicBob, sharedBob Key
	testTimes := 1 << 10

	for i := 0; i < testTimes; i++ {
		_, _ = rand.Read(secretAlice[:])
		_, _ = rand.Read(secretBob[:])

		KeyGen(&publicAlice, &secretAlice)
		KeyGen(&publicBob, &secretBob)

		if ok := Shared(&sharedAlice, &secretAlice, &publicBob); !ok {
			test.ReportError(t, ok, true, secretAlice, publicBob)
		}
		if ok := Shared(&sharedBob, &secretBob, &publicAlice); !ok {
			test.ReportError(t, ok, true, secretBob, publicAlice)
		}

		got := sharedAlice
		want := sharedBob
		if !bytes.Equal(got[:], want[:]) {
			test.ReportError(t, got, want, secretAlice, secretBob)
		}
	}
}

func TestDHLowOrder(t *testing.T) {
	var secretAlice, validPublicAlice, invalidPublicAlice, sharedAlice Key
	var secretBob, publicBob, sharedBob Key

	t.Run("zeroPoint", func(t *testing.T) {
		testTimes := 1 << 10

		for i := 0; i < testTimes; i++ {
			_, _ = rand.Read(secretAlice[:])
			_, _ = rand.Read(secretBob[:])

			KeyGen(&validPublicAlice, &secretAlice)
			KeyGen(&publicBob, &secretBob)

			zeroPoint := fourq.Point{}
			zeroPoint.SetIdentity()
			zeroPoint.Marshal((*[Size]byte)(&invalidPublicAlice))

			ok := Shared(&sharedAlice, &secretAlice, &publicBob)
			test.CheckOk(ok, "shared must not fail", t)

			ok = Shared(&sharedBob, &secretBob, &validPublicAlice)
			test.CheckOk(ok, "shared must not fail", t)

			invalid := Shared(&sharedBob, &secretBob, &invalidPublicAlice)
			test.CheckOk(!invalid, "shared must fail", t)
		}
	})

	t.Run("lowOrderPoint", func(t *testing.T) {
		KeyGen(&validPublicAlice, &secretAlice)
		KeyGen(&publicBob, &secretBob)

		// Point of order 56
		lowOrderPoint := fourq.Point{
			X: fourq.Fq{
				fourq.Fp{0xc0, 0xe5, 0x21, 0x04, 0xaa, 0xe1, 0x93, 0xd8, 0x9b, 0x50, 0x42, 0x54, 0xd6, 0x46, 0x86, 0x74},
				fourq.Fp{0x21, 0x25, 0x4d, 0x9a, 0xda, 0x8f, 0xad, 0x28, 0xa2, 0x3d, 0xfd, 0x02, 0x13, 0xea, 0xd2, 0x56},
			},
			Y: fourq.Fq{
				fourq.Fp{0xaf, 0x71, 0xe4, 0x3b, 0x22, 0x21, 0x41, 0xef, 0x12, 0xba, 0x67, 0x02, 0x57, 0x1, 0xe5, 0x58},
				fourq.Fp{0x0e, 0x1a, 0xf5, 0xe5, 0xb8, 0x24, 0x9c, 0xe0, 0xed, 0xc3, 0xc4, 0x69, 0x7, 0x32, 0x8e, 0x2c},
			},
		}

		ok := lowOrderPoint.IsOnCurve()
		test.CheckOk(ok, "point is on curve", t)

		lowOrderPoint.Marshal((*[Size]byte)(&invalidPublicAlice))
		invalid := Shared(&sharedBob, &secretBob, &invalidPublicAlice)
		test.CheckOk(!invalid, "shared must fail", t)
	})
}

func BenchmarkDH(b *testing.B) {
	var secret, public, shared Key
	_, _ = rand.Read(secret[:])
	_, _ = rand.Read(public[:])

	b.Run("keygen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			KeyGen(&public, &secret)
		}
	})
	b.Run("shared", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Shared(&shared, &secret, &public)
		}
	})
}

func ExampleKey() {
	var AliceSecret, BobSecret,
		AlicePublic, BobPublic,
		AliceShared, BobShared Key

	// Generating Alice's secret and public keys
	_, _ = io.ReadFull(rand.Reader, AliceSecret[:])
	KeyGen(&AlicePublic, &AliceSecret)

	// Generating Bob's secret and public keys
	_, _ = io.ReadFull(rand.Reader, BobSecret[:])
	KeyGen(&BobPublic, &BobSecret)

	// Deriving Alice's shared key
	Shared(&AliceShared, &AliceSecret, &BobPublic)

	// Deriving Bob's shared key
	Shared(&BobShared, &BobSecret, &AlicePublic)

	fmt.Println(AliceShared == BobShared)
	// Output: true
}
