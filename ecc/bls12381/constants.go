package bls12381

var (
	g1ParamB  = fp{4}  // 4
	g1Param3B = fp{12} // 3*G1ParamB
	genG1X    = fp{
		0xfb3af00adb22c6bb, 0x6c55e83ff97a1aef, 0xa14e3a3f171bac58,
		0xc3688c4f9774b905, 0x2695638c4fa9ac0f, 0x17f1d3a73197d794,
	}
	genG1Y = fp{
		0xcaa232946c5e7e1, 0xd03cc744a2888ae4, 0xdb18cb2c04b3ed,
		0xfcf5e095d5d00af6, 0xa09e30ed741d8ae4, 0x8b3f481e3aaa0f1,
	}
)
