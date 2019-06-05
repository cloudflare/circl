// Package x25519 provides Diffie-Hellman functions as specified in RFC-7748.
//
// References:
//  - Curve25519 https://cr.yp.to/ecdh.html
//  - RFC7748 https://rfc-editor.org/rfc/rfc7748.txt
package x25519

// Size is the length in bytes of a X25519 key.
const Size = 32

// Key represents a X25519 key.
type Key [Size]byte

// X25519 instantiates a receiver able to perform X25519 Diffie-Hellman operations.
type X25519 struct{}

// KeyGen obtains a public key given a secret key.
func (x *X25519) KeyGen(public, secret *Key) {
	c255.ladderJoye(public.clamp(secret))
}

// Shared calculates Alice's shared key from Alice's secret key and Bob's public key.
func (x *X25519) Shared(shared, secret, public *Key) {
	p := *public
	p[31] &= (1 << (255 % 8)) - 1
	c255.ladderMontgomery(shared.clamp(secret), &p)
}

func (k *Key) clamp(in *Key) *Key {
	*k = *in
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k
}
