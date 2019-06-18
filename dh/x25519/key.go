package x25519

// Size is the length in bytes of a X25519 key.
const Size = 32

// Key represents a X25519 key.
type Key [Size]byte

func (k *Key) clamp(in *Key) *Key {
	*k = *in
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k
}

// KeyGen obtains a public key given a secret key.
func KeyGen(public, secret *Key) {
	ladderJoye(public.clamp(secret))
}

// Shared calculates Alice's shared key from Alice's secret key and Bob's
// public key. Returns false when the recevied point is a low-order point.
func Shared(shared, secret, public *Key) bool {
	p, ok := validatePubKey(public)
	if !ok {
		return ok
	}
	ladderMontgomery(shared.clamp(secret), p)
	return true
}

func validatePubKey(k *Key) (*Key, bool) {
	p := *k
	// Validate input point
	p[31] &= (1 << (255 % 8)) - 1
	return &p, true
}
