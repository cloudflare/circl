package ed448_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/sign/ed448"
)

func TestWrongPublicKey(t *testing.T) {
	wrongPublicKeys := [...][ed448.Size]byte{
		{ // y = p
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		},
		{ // y > p
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		},
		{ // x^2 = u/v = (y^2-1)/(dy^2-1) is not a quadratic residue
			0xa4, 0x8b, 0xae, 0x31, 0x1b, 0x3a, 0xe5, 0x62,
			0x3d, 0x6f, 0x2d, 0xbe, 0x8b, 0xb4, 0xd3, 0x21,
			0x0f, 0x04, 0x0a, 0x7e, 0xf2, 0x25, 0x87, 0xc3,
			0xc0, 0x1e, 0xe1, 0xf4, 0x6d, 0xc7, 0x28, 0x8f,
			0x8b, 0xb9, 0x9f, 0x3d, 0x02, 0xb0, 0xc0, 0xa8,
			0xe7, 0xe3, 0x4f, 0xb2, 0x82, 0x64, 0x98, 0x4a,
			0x84, 0x73, 0xd7, 0x57, 0x6a, 0x39, 0x90, 0xa3,
		},
		{ // y = 1 and x^2 = u/v = 0, and the sign of X is 1
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
		},
		{ // y = -1 and x^2 = u/v = 0, and the sign of X is 1
			0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80,
		},
	}
	sig := (&[ed448.SignatureSize]byte{})[:]
	for _, public := range wrongPublicKeys {
		got := ed448.Verify(public[:], []byte(""), []byte(""), sig)
		want := false
		if got != want {
			test.ReportError(t, got, want, public)
		}
	}
}

func TestSigner(t *testing.T) {
	seed := make(ed448.PrivateKey, ed448.Size)
	_, _ = rand.Read(seed)
	key := ed448.NewKeyFromSeed(seed)

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
	if len(sig) != ed448.SignatureSize {
		got := len(sig)
		want := ed448.SignatureSize
		test.ReportError(t, got, want)
	}

	pubKey := key.GetPublic()
	pubSigner, ok := signer.Public().(ed448.PublicKey)
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

	got := ed448.Verify(pubSigner, msg, nil, sig)
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
		key, _ := ed448.GenerateKey(nil)
		_, got := key.Sign(nil, msg[:], ops)
		want := errors.New("ed448: cannot sign hashed message")
		if got.Error() != want.Error() {
			test.ReportError(t, got, want)
		}
	})
	t.Run("badReader", func(t *testing.T) {
		_, got := ed448.GenerateKey(badReader{})
		want := errors.New("cannot read")
		if got.Error() != want.Error() {
			test.ReportError(t, got, want)
		}
	})
	t.Run("wrongSeedSize", func(t *testing.T) {
		var seed [256]byte
		var want error
		got := test.CheckPanic(func() { ed448.NewKeyFromSeed(seed[:]) })
		if got != want {
			test.ReportError(t, got, want)
		}
	})
	t.Run("bigContext", func(t *testing.T) {
		var msg [16]byte
		var ctx [256]byte
		var want error
		key, _ := ed448.GenerateKey(nil)
		got := test.CheckPanic(func() { ed448.Sign(key, msg[:], ctx[:]) })
		if got != want {
			test.ReportError(t, got, want)
		}
	})
}

func BenchmarkEd448(b *testing.B) {
	msg := make([]byte, 128)
	ctx := make([]byte, 128)
	_, _ = rand.Read(msg)
	_, _ = rand.Read(ctx)

	b.Run("keygen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ed448.GenerateKey(rand.Reader)
		}
	})
	b.Run("sign", func(b *testing.B) {
		key, _ := ed448.GenerateKey(rand.Reader)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ed448.Sign(key, msg, ctx)
		}
	})
	b.Run("verify", func(b *testing.B) {
		key, _ := ed448.GenerateKey(rand.Reader)
		sig := ed448.Sign(key, msg, ctx)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ed448.Verify(key.GetPublic(), msg, ctx, sig)
		}
	})
}

func Example_ed448() {
	// import "github.com/cloudflare/circl/sign/ed448"

	// Generating Alice's key pair
	keys, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		panic("error on generating keys")
	}

	// Alice signs a message.
	message := []byte("A message to be signed")
	context := []byte("This is a context string")
	signature := ed448.Sign(keys, message, context)

	// Anyone can verify the signature using Alice's public key.
	ok := ed448.Verify(keys.GetPublic(), message, context, signature)
	fmt.Println(ok)
	// Output: true
}
