package group

import (
	"math/big"
)

var (
	zero *big.Int = big.NewInt(0)
	// One represents one in big.Int
	One *big.Int = big.NewInt(1)
	// Two represents two in big.Int
	Two *big.Int = big.NewInt(2)
	// MinusOne represents minus one in big.Int
	MinusOne *big.Int = big.NewInt(-1)
)

// Equals returns big.Int(1) if a == b and big.Int(0) otherwise
func Equals(a, b *big.Int) *big.Int {
	cmp := big.NewInt(int64(a.Cmp(b)))
	absCmp := new(big.Int).Abs(cmp)
	ad := new(big.Int).Add(absCmp, One)
	m := new(big.Int).Mod(ad, Two)
	return m
}

// cmov is a constant-time big.Int conditional selector, returning b if c is 1,
// and a if c = 0
func cMov(a, b, c *big.Int) *big.Int {
	s := new(big.Int).Sub(One, c)
	m1 := new(big.Int).Mul(c, b)
	m2 := new(big.Int).Mul(s, a)
	return new(big.Int).Add(m1, m2)
}

// Sgn0 returns -1 if x is negative (in little-endian sense) and 1 if x is positive
func Sgn0(x *big.Int) *big.Int {
	m := new(big.Int).Mod(x, Two)
	res := Equals(m, One)
	sign := cMov(One, MinusOne, res)
	zeroCmp := Equals(x, zero)
	sign = cMov(sign, zero, zeroCmp)
	sZeroCmp := Equals(sign, zero)
	return cMov(sign, One, sZeroCmp)
}
