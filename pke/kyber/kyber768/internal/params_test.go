package internal

import (
	"testing"
)

func TestNewKeyFromSeed(t *testing.T) {
	var seed [32]byte
	var ppk [PublicKeySize]byte
	var psk [PrivateKeySize]byte

	for i := 0; i < 32; i++ {
		seed[i] = uint8(i)
	}
	pk, sk := NewKeyFromSeed(seed[:])
	pk.Pack(ppk[:])
	sk.Pack(psk[:])

	if hexHash(ppk[:]) != "c8d2666793358e30" {
		t.Fatal()
	}
	if hexHash(psk[:]) != "bced10f66aa95b77" {
		t.Fatal()
	}
}
