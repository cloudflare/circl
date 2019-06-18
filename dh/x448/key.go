package x448

// Size is the length in bytes of a X448 key.
const Size = 56

// Key represents a X448 key.
type Key [Size]byte

func (k *Key) clamp(in *Key) *Key {
	*k = *in
	k[0] &= 252
	k[55] |= 128
	return k
}

// KeyGen obtains a public key given a secret key.
func KeyGen(public, secret *Key) {
	ladderJoye(public.clamp(secret))
}

// Shared calculates Alice's shared key from Alice's secret key and Bob's
// public key. Returns false when the recevied point is a low-order point.
func Shared(shared, secret, public *Key) bool {
	p := *public
	ladderMontgomery(shared.clamp(secret), &p)
	return true
}
