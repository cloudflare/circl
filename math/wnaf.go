package math

import (
	"math/big"
)

// OmegaNAFRegular obtains the window-w Non-Adjacent of n such that n>0 and odd.
// Alg.6 in Bos et al. (eprint.iacr.org/2014/130)
// Return a list L such that n = li*2^(w-1)
func OmegaNAFRegular(n *big.Int, w uint) []int32 {
	if n.Sign() <= 0 || n.Bit(0) == 0 {
		panic("n must be non-zero, odd, and positive")
	}
	lenN := (uint(n.BitLen()) + (w - 1) - 1) / (w - 1) // len = ceil(BitLen/(w-1))
	wnaf := make([]int32, lenN+2)
	var k, v big.Int
	k.Set(n)

	var i uint
	for i = 0; i < lenN; i++ {
		words := k.Bits()
		value := int(words[0] & ((1 << w) - 1))
		value -= 1 << (w - 1)
		wnaf[i] = int32(value)
		v.SetInt64(int64(value))
		k.Sub(&k, &v)
		k.Rsh(&k, w-1)
	}
	wnaf[i] = int32(k.Int64())
	return wnaf[:i+1]
}

// OmegaNAF obtains the window-w Non-Adjacent of a positive number n.
func OmegaNAF(n *big.Int, w uint) []int32 {
	if n.Sign() < 0 {
		panic("n must be positive")
	}

	wnaf := make([]int32, n.BitLen()+1)
	var k, v big.Int
	k.Set(n)

	i := 0
	for ; k.Sign() > 0; i++ {
		value := int(0)
		if k.Bit(0) == 1 {
			words := k.Bits()
			value = int(words[0] & ((1 << w) - 1))
			if value >= (1 << (w - 1)) {
				value -= 1 << w
			}
			v.SetInt64(int64(value))
			k.Sub(&k, &v)
		}
		wnaf[i] = int32(value)
		k.Rsh(&k, 1)
	}
	return wnaf[:i]
}
