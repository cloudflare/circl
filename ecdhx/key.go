// +build amd64

package ecdhx

//go:generate go run templates/gen.go

import (
	"crypto/rand"
	"fmt"
	"github.com/cloudflare/circl/ecdhx/field"
)

// SizeKey255 size in bytes of the key
const SizeKey255 = 32

// SizeKey448 size in bytes of the key
const SizeKey448 = 56

// Key255 is a key
type Key255 [SizeKey255]byte

// Key448 is a key
type Key448 [SizeKey448]byte

func random(k []byte) {
	if _, err := rand.Read(k); err != nil {
		panic("Error reading random bytes")
	}
}

// RandomKey255 returns a pseudo-random generated key for X25519
func RandomKey255() (key Key255) { random(key[:]); return }

// RandomKey448 returns a pseudo-random generated key for X448
func RandomKey448() (key Key448) { random(key[:]); return }

// GetBase255 returns a key with the x-coordinate of the generator of Curve25519
func GetBase255() Key255 { return Key255{byte(x255.xCoord)} }

// GetBase448 returns a key with the x-coordinate of the generator of Curve448
func GetBase448() Key448 { return Key448{byte(x448.xCoord)} }

func (k *Key255) clamp() *Key255 {
	kk := *k
	kk[0] &= 248
	kk[32-1] &= 127
	kk[32-1] |= 64
	return &kk
}

func (k *Key448) clamp() *Key448 {
	kk := *k
	kk[0] &= 252
	kk[56-1] |= 128
	return &kk
}

// KeyGen calculates a public key from a given secret key k
func (k *Key255) KeyGen() (public Key255) {
	kk := k.clamp()
	xkP := x255.ladderJoye(kk[:])
	copy(public[:], xkP)
	return public
}

// Shared generates a shared secret using Alice's secret and Bob's public keys
func (k *Key255) Shared(public Key255) (shared Key255) {
	// [RFC-7748] When receiving such an array, implementations
	// of X25519 (but not X448) MUST mask the most significant
	// bit in the final byte.
	var xP field.Element255
	copy(xP[:], public[:])
	xP[SizeKey255-1] &= (1 << (255 % 8)) - 1

	kk := k.clamp()
	xkP := x255.ladderMontgomery(kk[:], xP[:])
	copy(shared[:], xkP)
	return shared
}

// KeyGen calculates a public key from a given secret key k
func (k *Key448) KeyGen() (public Key448) {
	kk := k.clamp()
	xkP := x448.ladderJoye(kk[:])
	copy(public[:], xkP)
	return public
}

// Shared generates a shared secret using Alice's secret and Bob's public keys
func (k *Key448) Shared(public Key448) (shared Key448) {
	var xP field.Element448

	copy(xP[:], public[:])
	kk := k.clamp()
	xkP := x448.ladderMontgomery(kk[:], xP[:])
	copy(shared[:], xkP)
	return shared
}

func toString(k []byte) string {
	s := ""
	for _, ki := range k {
		s += fmt.Sprintf("%02x", ki)
	}
	return s
}

// String returns the hexadecimal representation of the key.
func (k *Key255) String() string { return toString(k[:]) }

// String returns the hexadecimal representation of the key.
func (k *Key448) String() string { return toString(k[:]) }
