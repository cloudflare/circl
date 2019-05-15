package math

import (
	"math/big"
)

// SignedDigit obtains the signed-digit recoding of n such that n>0 and odd and
// returns a list L such that n = sum( L[i]*2^(w-1) ) and L[i] are odd numbers
// in the set {±1, ±3, ..., ±2^(w-1)-1}.
//
// References:
//  - Alg.6 in "Exponent Recoding and Regular Exponentiation Algorithms"
//    by Joye-Tunstall. http://doi.org/10.1007/978-3-642-02384-2_21
//  - Alg.6 in "Selecting Elliptic Curves for Cryptography: An Efficiency and
//    Security Analysis" by Bos et al. http://doi.org/10.1007/s13389-015-0097-y
func SignedDigit(n *big.Int, w uint) []int32 {
	if n.Sign() <= 0 || n.Bit(0) == 0 {
		panic("n must be non-zero, odd, and positive")
	}
	lenN := (uint(n.BitLen()) + (w - 1) - 1) / (w - 1) // ceil(n.BitLen()/(w-1))
	L := make([]int32, lenN+2)
	var k, v big.Int
	k.Set(n)

	var i uint
	for i = 0; i < lenN; i++ {
		words := k.Bits()
		value := int(words[0] & ((1 << w) - 1))
		value -= 1 << (w - 1)
		L[i] = int32(value)
		v.SetInt64(int64(value))
		k.Sub(&k, &v)
		k.Rsh(&k, w-1)
	}
	L[i] = int32(k.Int64())
	return L[:i+1]
}

// OmegaNAF obtains the window-w Non-Adjacent Form of a positive number n.
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
