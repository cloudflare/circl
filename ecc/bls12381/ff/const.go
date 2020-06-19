package ff

import "math/big"

var (
	blsPrime *big.Int

	frob6V1  = Fp2{}
	frob6V2  = Fp2{}
	frob12W1 = Fp6{}
)

func init() {
	blsPrime = new(big.Int)
	blsPrime.SetString("0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 0)

	frob6V1[0].SetString("0x0")
	frob6V1[1].SetString("0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac")
	frob6V2[0].SetString("0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad")
	frob6V2[1].SetString("0x0")

	frob12W1[0][0].SetString("0x1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8")
	frob12W1[0][1].SetString("0xfc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3")
	frob12W1[1][0].SetString("0x0")
	frob12W1[1][1].SetString("0x0")
	frob12W1[2][0].SetString("0x0")
	frob12W1[2][1].SetString("0x0")
}
