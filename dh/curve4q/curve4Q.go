package curve4q

import "github.com/cloudflare/circl/ecc/fourq"

// Size is the size in bytes of keys.
const Size = 32

// Key represents a public or private key of FourQ.
type Key [Size]byte

// KeyGen calculates a public key k from a secret key.
func KeyGen(public, secret *Key) {
	var P fourq.Point
	P.ScalarBaseMult((*[Size]byte)(secret))
	P.Marshal((*[Size]byte)(public))
}

// Shared calculates a shared key k from Alice's secret and Bob's public key.
// Returns true on success.
//
// The public key is decoded leniently (see fourq.Point.Unmarshal) and the
// cofactor is cleared during scalar multiplication. Hence public keys must
// not be treated as unique identifiers without canonicalization.
func Shared(shared, secret, public *Key) bool {
	var P, Q fourq.Point
	ok := P.Unmarshal((*[Size]byte)(public))
	if !ok {
		return false
	}
	Q.ScalarMult((*[Size]byte)(secret), &P)
	Q.Marshal((*[Size]byte)(shared))
	return !Q.IsIdentity() && Q.IsOnCurve()
}
