package ff

import "math/big"

var (
	blsPrime *big.Int

	frob12_1 = Fp2{} // (u+1)^(1*(p-1)/6)
	frob12_2 = Fp2{} // (u+1)^(2*(p-1)/6)
	frob12_3 = Fp2{} // (u+1)^(3*(p-1)/6)
	frob12_4 = Fp2{} // (u+1)^(4*(p-1)/6)
	frob12_5 = Fp2{} // (u+1)^(5*(p-1)/6)
)

func init() {
	blsPrime = new(big.Int)
	blsPrime.SetString("0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 0)
	frob12_1[0].SetString("0x1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8")
	frob12_1[1].SetString("0xfc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3")
	frob12_2[0].SetString("0x0")
	frob12_2[1].SetString("0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac")
	frob12_3[0].SetString("0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09")
	frob12_3[1].SetString("0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09")
	frob12_4[0].SetString("0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad")
	frob12_4[1].SetString("0x0")
	frob12_5[0].SetString("0x5b2cfd9013a5fd8df47fa6b48b1e045f39816240c0b8fee8beadf4d8e9c0566c63a3e6e257f87329b18fae980078116")
	frob12_5[1].SetString("0x144e4211384586c16bd3ad4afa99cc9170df3560e77982d0db45f3536814f0bd5871c1908bd478cd1ee605167ff82995")
}
