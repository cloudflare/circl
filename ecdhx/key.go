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

// XKey provides Diffie-Hellman X operations
type XKey interface {
	Size() int        // Length in bytes of the key
	KeyGen() XKey     // Generates a public key using the receiver as a secret key
	Shared(XKey) XKey // Generates a shared secret using the receiver as a secret key and the parameter as the public key
}

// Key255 is a key for X25519 Diffie-Hellman protocol
type Key255 [SizeKey255]byte

// Key448 is a key for X448 Diffie-Hellman protocol
type Key448 [SizeKey448]byte

func random(k []byte) {
	if _, err := rand.Read(k); err != nil {
		panic("Error reading random bytes")
	}
}

// RandomKey255 returns a pseudo-random generated key for X25519
func RandomKey255() XKey { var k Key255; random(k[:]); return k }

// RandomKey448 returns a pseudo-random generated key for X448
func RandomKey448() XKey { var k Key448; random(k[:]); return k }

// XKeyFromSlice converts a slice into a key if the size of s is either SizeKey255 of SizeKey448
func XKeyFromSlice(s []byte) XKey {
	switch len(s) {
	case SizeKey255:
		var k Key255
		copy(k[:], s)
		return k
	case SizeKey448:
		var k Key448
		copy(k[:], s)
		return k
	default:
		panic("Unsupported key size")
	}
}

// GetBase255 returns a key with the x-coordinate of the generator of Curve25519
func GetBase255() XKey { return Key255{byte(x255.xCoord)} }

// GetBase448 returns a key with the x-coordinate of the generator of Curve448
func GetBase448() XKey { return Key448{byte(x448.xCoord)} }

func (k Key255) clamp() *Key255 {
	kk := k
	kk[0] &= 248
	kk[SizeKey255-1] &= 127
	kk[SizeKey255-1] |= 64
	return &kk
}

func (k Key448) clamp() *Key448 {
	kk := k
	kk[0] &= 252
	kk[SizeKey448-1] |= 128
	return &kk
}

// Size is the lenght in bytes of the key.
func (k Key255) Size() int { return SizeKey255 }

// KeyGen generates a public key using the receiver as a secret key
func (k Key255) KeyGen() XKey {
	var public Key255
	kk := k.clamp()
	xkP := x255.ladderJoye(kk[:])
	copy(public[:], xkP)
	return public
}

// Shared generates a shared secret using the receiver as a secret key and p as the public key
func (k Key255) Shared(p XKey) XKey {
	var shared Key255
	public, ok := p.(Key255)
	if !ok {
		panic("Wrong key type")
	}
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

// Size is the lenght in bytes of the key.
func (k Key448) Size() int { return SizeKey448 }

// KeyGen generates a public key using the receiver as a secret key
func (k Key448) KeyGen() XKey {
	var public Key448
	kk := k.clamp()
	xkP := x448.ladderJoye(kk[:])
	copy(public[:], xkP)
	return public
}

// Shared generates a shared secret using the receiver as a secret key and p as the public key
func (k Key448) Shared(p XKey) XKey {
	var shared Key448
	public, ok := p.(Key448)
	if !ok {
		panic("Wrong key type")
	}
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
func (k Key255) String() string { return toString(k[:]) }

// String returns the hexadecimal representation of the key.
func (k Key448) String() string { return toString(k[:]) }
