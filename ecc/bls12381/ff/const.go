package ff

import "math/big"

var blsPrime *big.Int

func init() {
	blsPrime = new(big.Int)
	blsPrime.SetString("0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 0)
}
