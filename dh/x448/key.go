// Package x448 provides Diffie-Hellman functions as specified in RFC-7748.
//
// References:
//  - Curve448 and Goldilocks https://eprint.iacr.org/2015/625
//  - RFC7748 https://rfc-editor.org/rfc/rfc7748.txt
package x448

// Size is the length in bytes of a X448 key.
const Size = 56

// Key represents a X448 key.
type Key [Size]byte

// X448 instantiates a receiver able to perform X448 Diffie-Hellman operations.
type X448 struct{}

// KeyGen obtains a public key given a secret key.
func (x *X448) KeyGen(public, secret *Key) {
	c448.ladderJoye(public.clamp(secret))
}

// Shared calculates Alice's shared key from Alice's secret key and Bob's public key.
func (x *X448) Shared(shared, secret, public *Key) {
	c448.ladderMontgomery(shared.clamp(secret), public)
}

func (k *Key) clamp(in *Key) *Key {
	*k = *in
	k[0] &= 252
	k[55] |= 128
	return k
}
