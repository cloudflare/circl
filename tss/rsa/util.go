package rsa

import (
	"crypto/rsa"
	"math/big"
)

var ONE = big.NewInt(1)

func calculateDelta(l int64) *big.Int {
	// ∆ = l!
	delta := big.Int{}
	delta.MulRange(1, l)
	return &delta
}

func createPrivateKey(p, q *big.Int, e int) *rsa.PrivateKey {
	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			E: e,
		},
		D:           nil,
		Primes:      []*big.Int{p, q},
		Precomputed: rsa.PrecomputedValues{},
	}
}
