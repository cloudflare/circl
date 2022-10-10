package rsa

import (
	"math/big"
)

func calculateDelta(l int64) *big.Int {
	// ∆ = l!
	delta := big.Int{}
	delta.MulRange(1, l)
	return &delta
}
