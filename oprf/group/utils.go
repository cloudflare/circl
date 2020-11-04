package group

import (
	"math/big"
)

var (
	zero *big.Int = big.NewInt(0)
	// One represents one in big.Int
	one *big.Int = big.NewInt(1)
	// Two represents two in big.Int
	two *big.Int = big.NewInt(2)
	// MinusOne represents minus one in big.Int
	minusOne *big.Int = big.NewInt(-1)
)

// Equals returns big.Int(1) if a == b and big.Int(0) otherwise
func equals(a, b *big.Int) *big.Int {
	cmp := big.NewInt(int64(a.Cmp(b)))
	absCmp := new(big.Int).Abs(cmp)
	ad := new(big.Int).Add(absCmp, one)
	m := new(big.Int).Mod(ad, two)
	return m
}

// cmov is a constant-time big.Int conditional selector, returning b if c is 1,
// and a if c = 0
func cMov(a, b, c *big.Int) *big.Int {
	s := new(big.Int).Sub(one, c)
	m1 := new(big.Int).Mul(c, b)
	m2 := new(big.Int).Mul(s, a)
	return new(big.Int).Add(m1, m2)
}

// sgn0 returns -1 if x is negative (in little-endian sense) and 1 if x is positive
func sgn0(x *big.Int) *big.Int {
	m := new(big.Int).Mod(x, two)
	res := equals(m, one)
	sign := cMov(one, minusOne, res)
	zeroCmp := equals(x, zero)
	sign = cMov(sign, zero, zeroCmp)
	sZeroCmp := equals(sign, zero)
	return cMov(sign, one, sZeroCmp)
}
