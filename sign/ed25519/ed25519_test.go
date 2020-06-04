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
	seed := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	_, _ = rand.Read(seed)
	key := ed25519.NewKeyFromSeed(seed)

	priv := key.GetPrivate()
	if !bytes.Equal(seed, priv) {
		got := priv
		want := seed
		test.ReportError(t, got, want)
	}
	priv = key.Seed()
	if !bytes.Equal(seed, priv) {
		got := priv
		want := seed
		test.ReportError(t, got, want)
	}

	signer := crypto.Signer(key)
	ops := crypto.Hash(0)
	msg := make([]byte, 16)
	_, _ = rand.Read(msg)
	sig, err := signer.Sign(nil, msg, ops)
	if err != nil {
		got := err
		var want error
		test.ReportError(t, got, want)
	}
	if len(sig) != ed25519.SignatureSize {
		got := len(sig)
		want := ed25519.SignatureSize
		test.ReportError(t, got, want)
	}

	pubKey := key.GetPublic()
	pubSigner, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		got := ok
		want := true
		test.ReportError(t, got, want)
	}
	if !bytes.Equal(pubKey, pubSigner) {
		got := pubSigner
		want := pubKey
		test.ReportError(t, got, want)
	}

	got := ed25519.Verify(pubSigner, msg, sig)
	want := true
	if got != want {
		test.ReportError(t, got, want)
	}
}

type badReader struct{}

func (badReader) Read([]byte) (n int, err error) { return 0, errors.New("cannot read") }

func TestErrors(t *testing.T) {
	t.Run("badHash", func(t *testing.T) {
		var msg [16]byte
		ops := crypto.SHA224
		key, _ := ed25519.GenerateKey(nil)
		_, got := key.Sign(nil, msg[:], ops)
		want := errors.New("ed25519: expected unhashed message or message hashed with SHA-512")
		if got.Error() != want.Error() {
			test.ReportError(t, got, want)
		}
	})
	t.Run("badReader", func(t *testing.T) {
		_, got := ed25519.GenerateKey(badReader{})
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

func BenchmarkEd25519(b *testing.B) {
	msg := make([]byte, 128)
	_, _ = rand.Read(msg)

	b.Run("keygen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = ed25519.GenerateKey(rand.Reader)
		}
	})
	b.Run("sign", func(b *testing.B) {
		key, _ := ed25519.GenerateKey(rand.Reader)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = key.SignPure(msg, false)
		}
	})
	b.Run("verify", func(b *testing.B) {
		key, _ := ed25519.GenerateKey(rand.Reader)
		sig, _ := key.SignPure(msg, false)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ed25519.Verify(key.GetPublic(), msg, sig)
		}
	})
}

func Example_ed25519() {
	// import "github.com/cloudflare/circl/sign/ed25519"

	// Generating Alice's key pair
	keys, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic("error on generating keys")
	}

	// Alice signs a message.
	message := []byte("A message to be signed")
	signature, err := keys.SignPure(message, false)
	if err != nil {
		panic("error on signing message")
	}

	// Anyone can verify the signature using Alice's public key.
	ok := ed25519.Verify(keys.GetPublic(), message, signature)
	fmt.Println(ok)
	// Output: true
}
