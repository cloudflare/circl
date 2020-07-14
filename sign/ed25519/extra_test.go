package ed25519_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/sign/ed25519"
)

func TestWrongPublicKey(t *testing.T) {
	wrongPublicKeys := [...][ed25519.PublicKeySize]byte{
		{ // y = p
			0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
		},
		{ // y > p
			0xed + 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
		},
		{ // x^2 = u/v = (y^2-1)/(dy^2+1) is not a quadratic residue
			0x9a, 0x0a, 0xbe, 0xc6, 0x23, 0xcb, 0x5a, 0x23,
			0x4e, 0x49, 0xd8, 0x92, 0xc2, 0x72, 0xd5, 0xa8,
			0x27, 0xff, 0x42, 0x07, 0x7d, 0xe3, 0xf2, 0xb4,
			0x74, 0x75, 0x9d, 0x04, 0x34, 0xed, 0xa6, 0x70,
		},
		{ // y = 1 and x^2 = u/v = 0, and the sign of X is 1
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 | 0x80,
		},
		{ // y = -1 and x^2 = u/v = 0, and the sign of X is 1
			0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f | 0x80,
		},
	}
	sig := (&[ed25519.SignatureSize]byte{})[:]
	for _, public := range wrongPublicKeys {
		got := ed25519.Verify(public[:], []byte(""), sig)
		want := false
		if got != want {
			test.ReportError(t, got, want, public)
		}
	}
}

func TestSigner(t *testing.T) {
	seed := (&[ed25519.SeedSize]byte{})[:]
	_, _ = rand.Read(seed)
	key := ed25519.NewKeyFromSeed(seed)

	priv := key.Seed()
	if !bytes.Equal(seed, priv) {
		got := priv
		want := seed
		test.ReportError(t, got, want)
	}

	for _, o := range []ed25519.SignerOptions{
		{Scheme: ed25519.ED25519, Hash: crypto.Hash(0), Context: ""},
		{Scheme: ed25519.ED25519Ph, Hash: crypto.SHA512, Context: ""},
		{Scheme: ed25519.ED25519Ph, Hash: crypto.SHA512, Context: "non-empty"},
		{Scheme: ed25519.ED25519Ctx, Hash: crypto.Hash(0), Context: "non-empty"},
	} {
		testSigner(t, key, o)
	}
}

func testSigner(t *testing.T, signer crypto.Signer, ops ed25519.SignerOptions) {
	msg := make([]byte, 64)
	_, _ = rand.Read(msg)

	sig, err := signer.Sign(nil, msg, ops)
	if err != nil {
		got := err
		var want error
		test.ReportError(t, got, want, ops)
	}

	if len(sig) != ed25519.SignatureSize {
		got := len(sig)
		want := ed25519.SignatureSize
		test.ReportError(t, got, want, ops)
	}

	pubSigner, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		got := ok
		want := true
		test.ReportError(t, got, want, ops)
	}

	got := ed25519.VerifyAny(pubSigner, msg, sig, ops)
	want := true
	if got != want {
		test.ReportError(t, got, want, ops)
	}
}

type badReader struct{}

func (badReader) Read([]byte) (int, error) { return 0, errors.New("cannot read") }

func TestErrors(t *testing.T) {
	t.Run("badHash", func(t *testing.T) {
		var msg [16]byte
		ops := crypto.SHA224
		_, priv, _ := ed25519.GenerateKey(nil)
		_, got := priv.Sign(nil, msg[:], ops)
		want := errors.New("ed25519: bad hash algorithm")
		if got.Error() != want.Error() {
			test.ReportError(t, got, want)
		}
	})
	t.Run("badReader", func(t *testing.T) {
		_, _, got := ed25519.GenerateKey(badReader{})
		want := errors.New("cannot read")
		if got.Error() != want.Error() {
			test.ReportError(t, got, want)
		}
	})
	t.Run("wrongSeedSize", func(t *testing.T) {
		var seed [256]byte
		var want error
		got := test.CheckPanic(func() { ed25519.NewKeyFromSeed(seed[:]) })
		if got != want {
			test.ReportError(t, got, want)
		}
	})
}

func BenchmarkEd25519Ph(b *testing.B) {
	msg := make([]byte, 128)
	_, _ = rand.Read(msg)

	b.Run("Sign", func(b *testing.B) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		ctx := ""
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = ed25519.SignPh(key, msg, ctx)
		}
	})
	b.Run("Verify", func(b *testing.B) {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		ctx := ""
		sig := ed25519.SignPh(priv, msg, ctx)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ed25519.VerifyPh(pub, msg, sig, ctx)
		}
	})
}

func BenchmarkEd25519Ctx(b *testing.B) {
	ctx := "a context"
	msg := make([]byte, 128)
	_, _ = rand.Read(msg)
	b.Run("Sign", func(b *testing.B) {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = ed25519.SignWithCtx(priv, msg, ctx)
		}
	})
	b.Run("Verify", func(b *testing.B) {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		sig := ed25519.SignWithCtx(priv, msg, ctx)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ed25519.VerifyWithCtx(pub, msg, sig, ctx)
		}
	})
}

func Example_ed25519() {
	// import "github.com/cloudflare/circl/sign/ed25519"
	// import "crypto/rand"

	// Generating Alice's key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic("error on generating keys")
	}

	// Alice signs a message.
	message := []byte("A message to be signed")
	signature := ed25519.Sign(priv, message)

	// Anyone can verify the signature using Alice's public key.
	ok := ed25519.Verify(pub, message, signature)
	fmt.Println(ok)
	// Output: true
}

func ExampleSignPh() {
	// import "github.com/cloudflare/circl/sign/ed25519"
	// import "crypto/rand"

	// Generating Alice's key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic("error on generating keys")
	}

	// Alice signs a message.
	message := []byte("A message to be signed")
	ctx := "an optional context string"

	signature := ed25519.SignPh(priv, message, ctx)

	// Anyone can verify the signature using Alice's public key.
	ok := ed25519.VerifyPh(pub, message, signature, ctx)
	fmt.Println(ok)
	// Output: true
}

func ExampleSignWithCtx() {
	// import "github.com/cloudflare/circl/sign/ed25519"
	// import "crypto/rand"

	// Generating Alice's key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic("error on generating keys")
	}

	// Alice signs a message.
	message := []byte("A message to be signed")
	ctx := "a non-empty context string"

	signature := ed25519.SignWithCtx(priv, message, ctx)

	// Anyone can verify the signature using Alice's public key.
	ok := ed25519.VerifyWithCtx(pub, message, signature, ctx)
	fmt.Println(ok)
	// Output: true
}
