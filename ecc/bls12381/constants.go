package bls12381

import (
	"errors"

	"github.com/cloudflare/circl/ecc/bls12381/ff"
)

// Scalar represents positive integers in the range 0 <= x < Order.
type Scalar = ff.Scalar

const ScalarSize = ff.ScalarSize

// Order returns the order of the pairing groups, returned as a big-endian slice.
//
//	Order = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
func Order() []byte { return ff.ScalarOrder() }

var (
	bls12381 struct { // Let z be the BLS12 parameter.
		minusZ    [8]byte  //      (-z), (integer big-endian).
		oneMinusZ [8]byte  //     (1-z), (integer big-endian).
		g1Check   [16]byte // (z^2-1)/3, (integer big-endian).
	}
	g1Params struct{ b, _3b, genX, genY ff.Fp }
	g2Params struct{ b, _3b, genX, genY ff.Fp2 }

	// g1Isog11 is an isogeny of degree 11 from g1Iso(a,b) to G1 and is given
	// by rational maps:
	//  g1Iso(a,b) --> G1
	//  (x,y,z)    |-> (x,y,1)
	//                 (xNum/xDen, y * yNum/yDen, 1)
	//                 (xNum*yDen, y * yNum*xDen, z*xDen*yDen)
	// such that
	//  xNum = \sum ai * x^i * z^(n-1-i), for 0 <= i < n, and n=12.
	//  xDen = \sum bi * x^i * z^(n-1-i), for 0 <= i < n, and n=11.
	//  yNum = \sum ci * x^i * z^(n-1-i), for 0 <= i < n, and n=16.
	//  yDen = \sum di * x^i * z^(n-1-i), for 0 <= i < n, and n=16.
	g1Isog11 struct {
		a, b ff.Fp
		xNum [12]ff.Fp
		xDen [11]ff.Fp
		yNum [16]ff.Fp
		yDen [16]ff.Fp
	}

	// g2Isog3 is an isogeny of degree 3 from g2Iso(a,b) to G2 and is given
	// by rational maps:
	//  g2Iso(a,b) --> G2
	//  (x,y,z)    |-> (x,y,1)
	//                 (xNum/xDen, y * yNum/yDen, 1)
	//                 (xNum*yDen, y * yNum*xDen, z*xDen*yDen)
	// such that
	//  xNum = \sum ai * x^i * z^(n-1-i), for 0 <= i < n, and n=4.
	//  xDen = \sum bi * x^i * z^(n-1-i), for 0 <= i < n, and n=3.
	//  yNum = \sum ci * x^i * z^(n-1-i), for 0 <= i < n, and n=4.
	//  yDen = \sum di * x^i * z^(n-1-i), for 0 <= i < n, and n=4.
	g2Isog3 struct {
		a, b ff.Fp2
		xNum [4]ff.Fp2
		xDen [3]ff.Fp2
		yNum [4]ff.Fp2
		yDen [4]ff.Fp2
	}
	g1sswu struct {
		Z  ff.Fp    // Z = 11.
		c1 [48]byte // integer c1 = (p - 3) / 4 (big-endian)
		c2 ff.Fp
	}
	g2sswu struct {
		Z  ff.Fp2   // -(2 + I)
		c1 [95]byte // integer c1 = (p^2 - 9) / 16 (big-endian)
		c2 ff.Fp2   // sqrt(-1)
		c3 ff.Fp2   // sqrt(c2)
		c4 ff.Fp2   // sqrt(Z^3 / c3)
		c5 ff.Fp2   // sqrt(Z^3 / (c2 * c3))
	}
	g1Sigma struct {
		beta0 ff.Fp // beta0 = F(2)^(2*(p-1)/3) where F = GF(p).
		beta1 ff.Fp // beta1 = F(2)^(1*(p-1)/3) where F = GF(p).
	}
	g2Psi struct {
		alpha ff.Fp2 // alpha = w^2/Frob(w^2)
		beta  ff.Fp2 // beta = w^3/Frob(w^3)
	}
)

var (
	errInputLength = errors.New("incorrect input length")
	errEncoding    = errors.New("incorrect encoding")
)

func headerEncoding(isCompressed, isInfinity, isBigYCoord byte) byte {
	return (isBigYCoord&0x1)<<5 | (isInfinity&0x1)<<6 | (isCompressed&0x1)<<7
}

func err(e error) {
	if e != nil {
		panic(e)
	}
}

func init() {
	bls12381.oneMinusZ = [8]byte{ // (big-endian)
		0xd2, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	bls12381.minusZ = [8]byte{ // (big-endian)
		0xd2, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
	}
	bls12381.g1Check = [16]byte{ // (big-endian)
		0x39, 0x6c, 0x8c, 0x00, 0x55, 0x55, 0xe1, 0x56,
		0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 0x55, 0x55,
	}
	initG1Params()
	initG2Params()
	initG1Isog11()
	initG2Isog3()
	initG1sswu()
	initG2sswu()
	initSigma()
	initPsi()
}

func initG1Params() {
	g1Params.b.SetUint64(4)
	g1Params._3b.SetUint64(12)
	err(g1Params.genX.SetString("0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"))
	err(g1Params.genY.SetString("0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"))
}

func initG2Params() {
	g2Params.b[0].SetUint64(4)
	g2Params.b[1].SetUint64(4)
	g2Params._3b[0].SetUint64(12)
	g2Params._3b[1].SetUint64(12)
	err(g2Params.genX[0].SetString("0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"))
	err(g2Params.genX[1].SetString("0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"))
	err(g2Params.genY[0].SetString("0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"))
	err(g2Params.genY[1].SetString("0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"))
}

func initG1Isog11() {
	err(g1Isog11.a.SetString("0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d"))
	err(g1Isog11.b.SetString("0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0"))
	err(g1Isog11.xNum[0].SetString("0x11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7"))
	err(g1Isog11.xNum[1].SetString("0x17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb"))
	err(g1Isog11.xNum[2].SetString("0x0d54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0"))
	err(g1Isog11.xNum[3].SetString("0x1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861"))
	err(g1Isog11.xNum[4].SetString("0x0e99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9"))
	err(g1Isog11.xNum[5].SetString("0x1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983"))
	err(g1Isog11.xNum[6].SetString("0x0d6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84"))
	err(g1Isog11.xNum[7].SetString("0x17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e"))
	err(g1Isog11.xNum[8].SetString("0x080d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317"))
	err(g1Isog11.xNum[9].SetString("0x169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9e"))
	err(g1Isog11.xNum[10].SetString("0x10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7b"))
	err(g1Isog11.xNum[11].SetString("0x06e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229"))

	err(g1Isog11.xDen[0].SetString("0x08ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c"))
	err(g1Isog11.xDen[1].SetString("0x12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff"))
	err(g1Isog11.xDen[2].SetString("0x0b2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19"))
	err(g1Isog11.xDen[3].SetString("0x03425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8"))
	err(g1Isog11.xDen[4].SetString("0x13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e"))
	err(g1Isog11.xDen[5].SetString("0x0e7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5"))
	err(g1Isog11.xDen[6].SetString("0x0772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3a"))
	err(g1Isog11.xDen[7].SetString("0x14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e"))
	err(g1Isog11.xDen[8].SetString("0x0a10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641"))
	err(g1Isog11.xDen[9].SetString("0x095fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0a"))
	g1Isog11.xDen[10].SetOne()

	err(g1Isog11.yNum[0].SetString("0x090d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33"))
	err(g1Isog11.yNum[1].SetString("0x134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696"))
	err(g1Isog11.yNum[2].SetString("0x00cc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6"))
	err(g1Isog11.yNum[3].SetString("0x01f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb"))
	err(g1Isog11.yNum[4].SetString("0x08cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb"))
	err(g1Isog11.yNum[5].SetString("0x16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0"))
	err(g1Isog11.yNum[6].SetString("0x04ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2"))
	err(g1Isog11.yNum[7].SetString("0x0987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29"))
	err(g1Isog11.yNum[8].SetString("0x09fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587"))
	err(g1Isog11.yNum[9].SetString("0x0e1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30"))
	err(g1Isog11.yNum[10].SetString("0x19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132"))
	err(g1Isog11.yNum[11].SetString("0x18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e"))
	err(g1Isog11.yNum[12].SetString("0x0b182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8"))
	err(g1Isog11.yNum[13].SetString("0x0245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133"))
	err(g1Isog11.yNum[14].SetString("0x05c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b"))
	err(g1Isog11.yNum[15].SetString("0x15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604"))

	err(g1Isog11.yDen[0].SetString("0x16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1"))
	err(g1Isog11.yDen[1].SetString("0x1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d"))
	err(g1Isog11.yDen[2].SetString("0x058df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2"))
	err(g1Isog11.yDen[3].SetString("0x16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416"))
	err(g1Isog11.yDen[4].SetString("0x0be0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d"))
	err(g1Isog11.yDen[5].SetString("0x08d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac"))
	err(g1Isog11.yDen[6].SetString("0x166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c"))
	err(g1Isog11.yDen[7].SetString("0x16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9"))
	err(g1Isog11.yDen[8].SetString("0x1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a"))
	err(g1Isog11.yDen[9].SetString("0x167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55"))
	err(g1Isog11.yDen[10].SetString("0x04d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8"))
	err(g1Isog11.yDen[11].SetString("0x0accbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092"))
	err(g1Isog11.yDen[12].SetString("0x0ad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc"))
	err(g1Isog11.yDen[13].SetString("0x02660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7"))
	err(g1Isog11.yDen[14].SetString("0x0e0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8f"))
	g1Isog11.yDen[15].SetOne()
}

func initG2Isog3() {
	err(g2Isog3.a.SetString("0x00", "0xF0"))
	err(g2Isog3.b.SetString("0x03F4", "0x03F4"))

	err(g2Isog3.xNum[0].SetString(
		"0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6",
		"0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6",
	))
	err(g2Isog3.xNum[1].SetString(
		"0x00",
		"0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a",
	))
	err(g2Isog3.xNum[2].SetString(
		"0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e",
		"0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d",
	))
	err(g2Isog3.xNum[3].SetString(
		"0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1",
		"0x00",
	))

	err(g2Isog3.xDen[0].SetString(
		"0x00",
		"0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63",
	))
	err(g2Isog3.xDen[1].SetString(
		"0x0c",
		"0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f",
	))
	g2Isog3.xDen[2].SetOne()

	err(g2Isog3.yNum[0].SetString(
		"0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706",
		"0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706",
	))
	err(g2Isog3.yNum[1].SetString(
		"0x00",
		"0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be",
	))
	err(g2Isog3.yNum[2].SetString(
		"0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c",
		"0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f",
	))
	err(g2Isog3.yNum[3].SetString(
		"0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10",
		"0x00",
	))

	err(g2Isog3.yDen[0].SetString(
		"0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb",
		"0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb",
	))
	err(g2Isog3.yDen[1].SetString(
		"0x00",
		"0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3",
	))
	err(g2Isog3.yDen[2].SetString(
		"0x12",
		"0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99",
	))
	g2Isog3.yDen[3].SetOne()
}

func initG1sswu() {
	g1sswu.Z.SetUint64(11)
	g1sswu.c1 = [48]byte{ // (big-endian)
		0x06, 0x80, 0x44, 0x7a, 0x8e, 0x5f, 0xf9, 0xa6,
		0x92, 0xc6, 0xe9, 0xed, 0x90, 0xd2, 0xeb, 0x35,
		0xd9, 0x1d, 0xd2, 0xe1, 0x3c, 0xe1, 0x44, 0xaf,
		0xd9, 0xcc, 0x34, 0xa8, 0x3d, 0xac, 0x3d, 0x89,
		0x07, 0xaa, 0xff, 0xff, 0xac, 0x54, 0xff, 0xff,
		0xee, 0x7f, 0xbf, 0xff, 0xff, 0xff, 0xea, 0xaa,
	}
	err(g1sswu.c2.SetString("0x3d689d1e0e762cef9f2bec6130316806b4c80eda6fc10ce77ae83eab1ea8b8b8a407c9c6db195e06f2dbeabc2baeff5"))
}

func initG2sswu() {
	g2sswu.Z[1].SetUint64(1)
	g2sswu.Z[0].SetUint64(2)
	g2sswu.Z.Neg()
	g2sswu.c1 = [95]byte{ // (big-endian)
		0x2a, 0x43, 0x7a, 0x4b, 0x8c, 0x35, 0xfc, 0x74,
		0xbd, 0x27, 0x8e, 0xaa, 0x22, 0xf2, 0x5e, 0x9e,
		0x2d, 0xc9, 0x0e, 0x50, 0xe7, 0x04, 0x6b, 0x46,
		0x6e, 0x59, 0xe4, 0x93, 0x49, 0xe8, 0xbd, 0x05,
		0x0a, 0x62, 0xcf, 0xd1, 0x6d, 0xdc, 0xa6, 0xef,
		0x53, 0x14, 0x93, 0x30, 0x97, 0x8e, 0xf0, 0x11,
		0xd6, 0x86, 0x19, 0xc8, 0x61, 0x85, 0xc7, 0xb2,
		0x92, 0xe8, 0x5a, 0x87, 0x09, 0x1a, 0x04, 0x96,
		0x6b, 0xf9, 0x1e, 0xd3, 0xe7, 0x1b, 0x74, 0x31,
		0x62, 0xc3, 0x38, 0x36, 0x21, 0x13, 0xcf, 0xd7,
		0xce, 0xd6, 0xb1, 0xd7, 0x63, 0x82, 0xea, 0xb2,
		0x6a, 0xa0, 0x00, 0x01, 0xc7, 0x18, 0xe3,
	}
	err(g2sswu.c2.SetString("0x00", "0x01"))
	err(g2sswu.c3.SetString(
		"0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2",
		"0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09",
	))
	err(g2sswu.c4.SetString(
		"0x699be3b8c6870965e5bf892ad5d2cc7b0e85a117402dfd83b7f4a947e02d978498255a2aaec0ac627b5afbdf1bf1c90",
		"0x8157cd83046453f5dd0972b6e3949e4288020b5b8a9cc99ca07e27089a2ce2436d965026adad3ef7baba37f2183e9b5",
	))
	err(g2sswu.c5.SetString(
		"0xf5d0d63d2797471e6d39f306cc0dc0ab85de3bd9f39ce46f3649ac0de9e844417cc8de88716c1fd323fa68040801aea",
		"0xab1c2ffdd6c253ca155231eb3e71ba044fd562f6f72bc5bad5ec46a0b7a3b0247cf08ce6c6317f40edbc653a72dee17",
	))
}

func initSigma() {
	err(g1Sigma.beta0.SetString("0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac"))
	err(g1Sigma.beta1.SetString("0x5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe"))
}

func initPsi() {
	// ratioKummer sets z = t/Frob(t) if it falls in Fp2, panics otherwise.
	ratioKummer := func(z *ff.Fp2, t *ff.Fp12) {
		var r ff.Fp12
		r.Frob(t)
		r.Inv(&r)
		r.Mul(t, &r)
		if r[1].IsZero() != 1 || r[0][1].IsZero() != 1 || r[0][2].IsZero() != 1 {
			err(errors.New("failure of result to be in Fp2"))
		}
		*z = r[0][0]
	}

	w := &ff.Fp12{}
	w[1].SetOne()
	wsq := &ff.Fp12{}
	wsq.Sqr(w)
	ratioKummer(&g2Psi.alpha, wsq)
	wcube := &ff.Fp12{}
	wcube.Mul(wsq, w)
	ratioKummer(&g2Psi.beta, wcube)
}
