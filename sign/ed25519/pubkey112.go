// +build !go1.13

package ed25519

import (
	"bytes"
	"crypto"
)

// PublicKey is the type of Ed25519 public keys.
type PublicKey []byte

// Equal reports whether pub and x have the same value.
func (pub PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(PublicKey)
	if !ok {
		return false
	}
	return bytes.Equal(pub, xx)
}
