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

	if hexHash(ppk[:]) != "dcd0498733bdcda5" {
		t.Fatal()
	}
	if hexHash(psk[:]) != "fde000dd9e761431" {
		t.Fatal()
	}
}
