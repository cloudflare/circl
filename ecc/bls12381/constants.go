package bls12381

import (
	"fmt"

	"github.com/cloudflare/circl/ecc/bls12381/ff"
)

// Scalar represents positive integers in the range 0 <= x < Order.
type Scalar = ff.Scalar

const ScalarSize = ff.ScalarSize

// Order returns the order of the pairing groups, returned as a big-endian slice.
//  Order = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
func Order() []byte { return ff.ScalarOrder() }

var (
	g1Params struct {
		b, _3b, genX, genY ff.Fp
		cofactorSmall      [8]byte // (1-z), where z is the BLS12 parameter (big-endian).
	}
	g2Params struct{ b, _3b, genX, genY ff.Fp2 }
	g1Isog11 struct {
		a, b, c2 ff.Fp
		c1       [ff.FpSize]byte // integer c1 = (p - 3) / 4 (big-endian)
		xNum     [12]ff.Fp
		xDen     [11]ff.Fp
		yNum     [16]ff.Fp
		yDen     [16]ff.Fp
	}
	g1Check struct {
		coef  [16]byte // coef  = (z^2-1)/3, where z is the BLS12 parameter (big-endian).
		beta0 ff.Fp    // beta0 = F(2)^(2*(p-1)/3) where F = GF(p).
		beta1 ff.Fp    // beta1 = F(2)^(1*(p-1)/3) where F = GF(p).
	}
	g2PsiCoeff struct {
		minusZ [8]byte // (-z), where z is the BLS12 parameter (big-endian).
		alpha  ff.Fp2  // alpha = w^2/Frob(w^2)
		beta   ff.Fp2  // beta = w^3/Frob(w^3)
	}
)

func err(e error) {
	if e != nil {
		panic(e)
	}
}

// ratioKummer returns t/Frob(t) if it falls in Fp2, and error otherwise.
func ratioKummer(t *ff.Fp12) (*ff.Fp2, error) {
	var r ff.Fp12
	r.Frob(t)
	r.Inv(&r)
	r.Mul(t, &r)
	if r[1].IsZero() != 1 || r[0][1].IsZero() != 1 || r[0][2].IsZero() != 1 {
		return nil, fmt.Errorf("failure of result %v to be in Fp2", r)
	}
	return &r[0][0], nil
}

func init() {
	g1Params.b.SetUint64(4)
	g1Params._3b.SetUint64(12)
	err(g1Params.genX.SetString("0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"))
	err(g1Params.genY.SetString("0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"))
	g1Params.cofactorSmall = [8]byte{0xd2, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01} // (big-endian)

	g2Params.b[0].SetUint64(4)
	g2Params.b[1].SetUint64(4)
	g2Params._3b[0].SetUint64(12)
	g2Params._3b[1].SetUint64(12)
	err(g2Params.genX[0].SetString("0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"))
	err(g2Params.genX[1].SetString("0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"))
	err(g2Params.genY[0].SetString("0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"))
	err(g2Params.genY[1].SetString("0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"))

	g1Isog11.c1 = [ff.FpSize]byte{ // (big-endian)
		0x06, 0x80, 0x44, 0x7a, 0x8e, 0x5f, 0xf9, 0xa6,
		0x92, 0xc6, 0xe9, 0xed, 0x90, 0xd2, 0xeb, 0x35,
		0xd9, 0x1d, 0xd2, 0xe1, 0x3c, 0xe1, 0x44, 0xaf,
		0xd9, 0xcc, 0x34, 0xa8, 0x3d, 0xac, 0x3d, 0x89,
		0x07, 0xaa, 0xff, 0xff, 0xac, 0x54, 0xff, 0xff,
		0xee, 0x7f, 0xbf, 0xff, 0xff, 0xff, 0xea, 0xaa,
	}
	err(g1Isog11.a.SetString("0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d"))
	err(g1Isog11.b.SetString("0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0"))
	err(g1Isog11.c2.SetString("0x3d689d1e0e762cef9f2bec6130316806b4c80eda6fc10ce77ae83eab1ea8b8b8a407c9c6db195e06f2dbeabc2baeff5"))

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

	err(g1Check.beta0.SetString("0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac"))
	err(g1Check.beta1.SetString("0x5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe"))

	g1Check.coef = [16]byte{0x39, 0x6c, 0x8c, 0x00, 0x55, 0x55, 0xe1, 0x56, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 0x55, 0x55} // (big-endian)

	initPsi()
}

func initPsi() {
	g2PsiCoeff.minusZ = [8]byte{0xd2, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00} // (big-endian)
	w := &ff.Fp12{}
	w[1].SetOne()
	wsq := &ff.Fp12{}
	wsq.Sqr(w)
	alpha, errval := ratioKummer(wsq)
	err(errval)
	g2PsiCoeff.alpha.Set(alpha)
	wcube := &ff.Fp12{}
	wcube.Mul(wsq, w)
	beta, errval := ratioKummer(wcube)
	err(errval)
	g2PsiCoeff.beta.Set(beta)
}
