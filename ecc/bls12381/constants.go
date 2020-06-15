package bls12381

import "github.com/cloudflare/circl/ecc/bls12381/ff"

var (
	g1ParamB  = ff.Fp{ /*4*/ }  // 4
	g1Param3B = ff.Fp{ /*12*/ } // 3*G1ParamB
	g1GenX    = ff.Fp{
		// 0xfb3af00adb22c6bb, 0x6c55e83ff97a1aef, 0xa14e3a3f171bac58,
		// 0xc3688c4f9774b905, 0x2695638c4fa9ac0f, 0x17f1d3a73197d794,
	}
	g1GenY = ff.Fp{
		// 0xcaa232946c5e7e1, 0xd03cc744a2888ae4, 0xdb18cb2c04b3ed,
		// 0xfcf5e095d5d00af6, 0xa09e30ed741d8ae4, 0x8b3f481e3aaa0f1,
	}
	g2ParamB   = ff.Fp2{}
	g2Param3B  = ff.Fp2{}
	g2GenX     = ff.Fp2{}
	g2GenY     = ff.Fp2{}
	primeOrder = Scalar{
		0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
		0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd, 0x53,
		0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33,
		0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73,
	}
)

func init() {
	g1ParamB.SetUint64(4)
	g1Param3B.SetUint64(12)
	g1GenX.SetString("0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb")
	g1GenY.SetString("0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1")

	g2ParamB[0].SetUint64(4)
	g2ParamB[1].SetUint64(4)
	g2Param3B[0].SetUint64(12)
	g2Param3B[1].SetUint64(12)
	g2GenX[0].SetString("0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8")
	g2GenX[1].SetString("0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e")
	g2GenY[0].SetString("0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801")
	g2GenY[1].SetString("0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be")
}
