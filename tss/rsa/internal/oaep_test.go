package internal

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"
)

func TestDecodeOAEP(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	label := []byte("threshold encryption")
	for _, size := range []int{0, 32, key.Size() - 2*sha256.Size - 2} {
		plaintext := bytes.Repeat([]byte{0x42}, size)
		ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, plaintext, label)
		if err != nil {
			t.Fatal(err)
		}
		block := new(big.Int).SetBytes(ciphertext)
		block.Exp(block, key.D, key.N)
		encoded := block.FillBytes(make([]byte, key.Size()))
		got, err := DecodeOAEP(bytes.Clone(encoded), label)
		if err != nil || !bytes.Equal(got, plaintext) {
			t.Fatalf("could not decode a %d-byte standard OAEP message: %v", size, err)
		}
		if _, err := DecodeOAEP(bytes.Clone(encoded), []byte("wrong label")); !errors.Is(err, rsa.ErrDecryption) {
			t.Fatalf("wrong label returned %v", err)
		}
		encoded[0] = 1
		if _, err := DecodeOAEP(encoded, label); !errors.Is(err, rsa.ErrDecryption) {
			t.Fatalf("nonzero first byte returned %v", err)
		}
	}
}

func TestDecodeOAEPRejectsMalformedPadding(t *testing.T) {
	labelHash := sha256.Sum256(nil)
	for _, padding := range [][]byte{{0, 0, 0}, {0, 2, 1}, {2, 1, 0}} {
		encoded := make([]byte, 1+2*sha256.Size+len(padding))
		seed := encoded[1 : 1+sha256.Size]
		database := encoded[1+sha256.Size:]
		copy(database, labelHash[:])
		copy(database[sha256.Size:], padding)
		hasher := sha256.New()
		MGF1XOR(database, hasher, seed)
		MGF1XOR(seed, hasher, database)
		if _, err := DecodeOAEP(encoded, nil); !errors.Is(err, rsa.ErrDecryption) {
			t.Errorf("malformed padding %x returned %v", padding, err)
		}
	}
	if _, err := DecodeOAEP(make([]byte, 2*sha256.Size+1), nil); !errors.Is(err, rsa.ErrDecryption) {
		t.Errorf("short block returned %v", err)
	}
}
