package curve4q

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

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
