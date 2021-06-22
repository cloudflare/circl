// Code generated from kyber512/internal/cpapke_test.go by gen.go

package internal

import (
	"crypto/rand"
	"testing"
)

func TestEncryptThenDecrypt(t *testing.T) {
	var seed [32]byte
	var coin [SeedSize]byte

	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
		coin[i] = byte(i)
	}

	for i := 0; i < 100; i++ {
		seed[0] = byte(i)
		pk, sk := NewKeyFromSeed(seed[:])

		for j := 0; j < 100; j++ {
			var msg, msg2 [PlaintextSize]byte
			var ct [CiphertextSize]byte

			_, _ = rand.Read(msg[:])
			_, _ = rand.Read(coin[:])

			pk.EncryptTo(ct[:], msg[:], coin[:])
			sk.DecryptTo(msg2[:], ct[:])

			if msg != msg2 {
				t.Fatalf("%v %v %v", ct, msg, msg2)
			}
		}
	}
}
