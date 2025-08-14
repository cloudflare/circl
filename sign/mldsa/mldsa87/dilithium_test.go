package mldsa87

import (
	"crypto"
	"crypto/rand"
	"testing"
)

func BenchmarkGenerateKey(b *testing.B) {
	for b.Loop() {
		_, _, _ = GenerateKey(rand.Reader)
	}
}

func BenchmarkPrivateKey_Sign(b *testing.B) {
	msg := make([]byte, 1024)
	rand.Read(msg)

	var opts noHashOptions

	_, sk, _ := GenerateKey(rand.Reader)

	for b.Loop() {
		_, _ = sk.Sign(rand.Reader, msg, &opts)
	}
}

func BenchmarkPublicKey_Verify(b *testing.B) {
	msg := make([]byte, 1024)
	rand.Read(msg)

	var opts noHashOptions

	pk, sk, _ := GenerateKey(rand.Reader)

	sig, err := sk.Sign(rand.Reader, msg, &opts)
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		if !Verify(pk, msg, nil, sig) {
			b.Fatal("signature verification failed")
		}
	}
}

type noHashOptions struct{}

func (n *noHashOptions) HashFunc() crypto.Hash {
	return 0
}
