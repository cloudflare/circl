// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package main_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/ecc"
	"github.com/cloudflare/circl/ecc/brainpool"
	"github.com/cloudflare/circl/ecc/nist"
	"github.com/cloudflare/circl/ecc/secg"
	"github.com/cloudflare/circl/ecc/x962"
	"github.com/cloudflare/circl/ecc/x963"
)

// 3*Basepoint for each curve
var testvec3G = []struct {
	curve elliptic.Curve
	x, y  string
}{
	// -------- Brainpool --------
	{
		curve: brainpool.P160t1(),
		x:     "0xc7fb4e367ed789413fc9648ce0e921156f37642b",
		y:     "0x554bba4e002e3f5c7cef7f0bd169cc5979d8ff3d",
	},
	{
		curve: brainpool.P160r1(),
		x:     "0x8a7c28a550682cda519ce7bc73778ea9ac7812b5",
		y:     "0x868562a3f2101faf2fb5ee7a0f366dcbac9147fe",
	},
	{
		curve: brainpool.P192t1(),
		x:     "0x1092182a330dcdbbab7bd585e1611b05d197df5745273fdc",
		y:     "0x65e8622349aa118d9e46dab8eddde2bcf7765f768c05e708",
	},
	{
		curve: brainpool.P192r1(),
		x:     "0x15372d94937774620bdbff366d5677d8464866c7b0b20626",
		y:     "0x240f7e24234c9ecc309f54b7d88002eaf78341ab1d1e4919",
	},
	{
		curve: brainpool.P224t1(),
		x:     "0x347945949fc2a5a3c21d6c34f880545b85f9283ffc900fa0be1efc11",
		y:     "0x545ec6fcdf28122f82bfc658dce53035eca6267d49199a0cc00cee8e",
	},
	{
		curve: brainpool.P224r1(),
		x:     "0x9051dae686fa68103a478db398818d048c2042f01f0ecab577e4598e",
		y:     "0xbaa97f6f99cabf4a626c056b63f21f793589d36cd5981a3579782900",
	},
	{
		curve: brainpool.P256t1(),
		x:     "0x46b2a45fdd881abea0cb4e5fea19c5a72d399245643b06e0fbe24a5e4058d806",
		y:     "0x4f88cd8d4bc69acc7b7032d98460b2c23160441f40562c00bee2aa7860c19aa8",
	},
	{
		curve: brainpool.P256r1(),
		x:     "0xa8f217b77338f1d4d6624c3ab4f6cc16d2aa843d0c0fca016b91e2ad25cae39d",
		y:     "0x4b49cafc7dac26bb0aa2a6850a1b40f5fac10e4589348fb77e65cc5602b74f9d",
	},
	{
		curve: brainpool.P320t1(),
		x:     "0x847758c1c7338efab1b79a22b4446f56c87fab0070b7858e8abdbbd94d454e0c340ebb42dcf91633",
		y:     "0x3d944522b6c1b7d42038e281d4d77ac75c2e0a37e33381c3f0d845cf32d54c39406ee208f7f322c1",
	},
	{
		curve: brainpool.P320r1(),
		x:     "0xc1e31fd7f03708ce169cfd15be47890edb83acdef8aef8ba0957fc7ac717c6efbce18f0bcf5e73c9",
		y:     "0xcdb9aece49778b79f7a6ef2ffa840297f67e4d269ad8a58e8a5f27ce8c5ada7d9303a9404c589400",
	},
	{
		curve: brainpool.P384t1(),
		x:     "0x3e7e83b88ba8d99a004f1c92ee361648a922f773f96d64b2bb66d1f3c0eeac30485cfef216f68b596b8861fbc005ea9",
		y:     "0x298585e0c24722037f09dd015c2fefeec87058d76a07fe43ed52e8641b7248d2c8baba631d9d68adc2bd7e748c753c0d",
	},
	{
		curve: brainpool.P384r1(),
		x:     "0x7b63205bf00ddae73b17452b6a27ebf53df581348c6949f83ee1b6fcc7463bbe3c11ef6596a3b8897d7cc85b3035f11f",
		y:     "0x761d3a4a5f8093775521a326bc02baaf7b2eb481ead16a5c7b2bd39462363e0373c0edaea3b8f59381d7129d48772eb3",
	},
	{
		curve: brainpool.P512t1(),
		x:     "0x6ebd6e634974f138300e1d9024e1132bf53bfdcb1d0142501efcbbd2a295f70fac1b86449310ab68d8c7e6aaafa22a0a4398aedacdcfadd2cbdd03a56ee4ff0d",
		y:     "0x2fbe930ec94f50e8031161d73095549c2d39e1085dedb61db91f1c931c1a0c1022effddc3f91bde114e87f77f544ee1ac6ddb5db1f55fe8406fb7f856ff951b0",
	},
	{
		curve: brainpool.P512r1(),
		x:     "0x8dd87e12b0a4cc436cdd42543f20afe907c80ef3bc2459309c09cefd830151bc1f6fb975ceecade4780ae53e1853d62f56e34abfa9ac7205d4abf882ccb8d94",
		y:     "0x26ef5c6e1dab71d756ff0067376fa7543d903b4a6334c4bba0b382e1716d843acdab8eb772327b3febfcb69c0f37c5f8cce5bc75d8de6495cdeafba05b02c37",
	},
	// -------- NIST --------
	{
		curve: nist.P192(),
		x:     "0x76e32a2557599e6edcd283201fb2b9aadfd0d359cbb263da",
		y:     "0x782c37e372ba4520aa62e0fed121d49ef3b543660cfd05fd",
	},
	{
		curve: nist.P224(),
		x:     "0xdf1b1d66a551d0d31eff822558b9d2cc75c2180279fe0d08fd896d04",
		y:     "0xa3f7f03cadd0be444c0aa56830130ddf77d317344e1af3591981a925",
	},
	{
		curve: nist.P256(),
		x:     "0x5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c",
		y:     "0x8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032",
	},
	{
		curve: nist.P384(),
		x:     "0x77a41d4606ffa1464793c7e5fdc7d98cb9d3910202dcd06bea4f240d3566da6b408bbae5026580d02d7e5c70500c831",
		y:     "0xc995f7ca0b0c42837d0bbe9602a9fc998520b41c85115aa5f7684c0edc111eacc24abd6be4b5d298b65f28600a2f1df1",
	},
	{
		curve: nist.P521(),
		x:     "0x1a73d352443de29195dd91d6a64b5959479b52a6e5b123d9ab9e5ad7a112d7a8dd1ad3f164a3a4832051da6bd16b59fe21baeb490862c32ea05a5919d2ede37ad7d",
		y:     "0x13e9b03b97dfa62ddd9979f86c6cab814f2f1557fa82a9d0317d2f8ab1fa355ceec2e2dd4cf8dc575b02d5aced1dec3c70cf105c9bc93a590425f588ca1ee86c0e5",
	},
	{
		curve: nist.K163(),
		x:     "0x2acfcfcc9a2af8e3f2828024f820033db20f69520",
		y:     "0x5729c47f915badc7b4c17df14e5804109ffecdfe4",
	},
	{
		curve: nist.B163(),
		x:     "0x634000577f86aa315009d6f9b906691f6edd691fe",
		y:     "0x401a3de0d6c2ec014e6fba5653587bd45dc2230be",
	},
	{
		curve: nist.K233(),
		x:     "0x4656e0aabbe341407715ca4a7fac287b41baa1f789c29bfa27e53a7a46",
		y:     "0xf79a7245fba513df787a64c618e97ebcc078638ebaaa562e9862bc00ce",
	},
	{
		curve: nist.B233(),
		x:     "0x80f50a330911bd753a76364595b9f0158c4d02a85cc0e3fb6ea0aef9ff",
		y:     "0x17a49033f12eb52675e98e6432cc27104bd5c42bcbe3daf76901c9b8743",
	},
	{
		curve: nist.K283(),
		x:     "0x15dccc30a8b1f5146412d51fec337741090321408aac521391ad36c5912e280124fe3b5",
		y:     "0x53fc9bed137312952ad97f6a98c4c7ac1b421635fbafe28898e9213d979d5b4d279f192",
	},
	{
		curve: nist.B283(),
		x:     "0xd257a925ba8bbf1a490a06a80d8338453a9a00eed2c51a90467a4283b3a4df9de2bc0b",
		y:     "0x22a7592959069fbbc245bee792106e995513d5f6837b90f291feb732b1cbe3427c8e585",
	},
	{
		curve: nist.K409(),
		x:     "0x15cdee83fc75049adc9ac4b259a4973fc82fe6c27ad22796b0992521eebfbae63aacd6cc7decd27453215a5c92a2eca614f2fa2",
		y:     "0x973314e9c9e2eb4cf9d70cfc9127619d5d190131a8c8638f96e859976d3b34db7ed3651bde3779a5d833a9d05952a7d4d06d16",
	},
	{
		curve: nist.B409(),
		x:     "0xd5f0e8b27d12d7a9dcea13a5cfb9dee62d63376e31f7666ba2ac2bf314b91420749ef549a17e5dc6815a7b044ff458c40c415",
		y:     "0x1db5b78d491e45cc58e9e44bd7e42537597b9aba85e2e3589f02d466ed31b816235f6d22679690002fcef2b5390f0de885e90be",
	},
	{
		curve: nist.K571(),
		x:     "0x287b0ccbb649860ccb56f10afea9090c8a05a351d2b70671084c563d37c6536b8be7b6130bfcd60e2111cd8a1283edf48970333c3906a61809d10bbfd4e016650ad4a749a68199a",
		y:     "0x2264fc0cb1b83968ff3f8f5689aeacd2b3cc9ce59ef83f0007e2da3045ac8ab2c0b43f4a2c9d2f29710cccee24286c3e4224614eba64f2f1629fd79168094130f31d6ce787cbd41",
	},
	{
		curve: nist.B571(),
		x:     "0x72d033e612ca6dd14c28f1f6689af9a97bba7fd88a25bae969dd1c91e75a9f680442dea747eab06e73b746911780505dab0e03149de396b1020fbaf55580cf4d6eb9738ce0d26f8",
		y:     "0x494ba50070ca0fc97e89f3ea55de5aed4d5bd139b3725618dfeb90152230aa53fa37b6e39baad54a77771f0df01bffee82fbb0bad45f2d5c89f704c6eba6722b1e4433638d87dda",
	},
	// -------- SECG --------
	{
		curve: secg.Secp192r1(),
		x:     "0x76e32a2557599e6edcd283201fb2b9aadfd0d359cbb263da",
		y:     "0x782c37e372ba4520aa62e0fed121d49ef3b543660cfd05fd",
	},
	{
		curve: secg.Secp224r1(),
		x:     "0xdf1b1d66a551d0d31eff822558b9d2cc75c2180279fe0d08fd896d04",
		y:     "0xa3f7f03cadd0be444c0aa56830130ddf77d317344e1af3591981a925",
	},
	{
		curve: secg.Secp256r1(),
		x:     "0x5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c",
		y:     "0x8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032",
	},
	{
		curve: secg.Secp384r1(),
		x:     "0x77a41d4606ffa1464793c7e5fdc7d98cb9d3910202dcd06bea4f240d3566da6b408bbae5026580d02d7e5c70500c831",
		y:     "0xc995f7ca0b0c42837d0bbe9602a9fc998520b41c85115aa5f7684c0edc111eacc24abd6be4b5d298b65f28600a2f1df1",
	},
	{
		curve: secg.Secp521r1(),
		x:     "0x1a73d352443de29195dd91d6a64b5959479b52a6e5b123d9ab9e5ad7a112d7a8dd1ad3f164a3a4832051da6bd16b59fe21baeb490862c32ea05a5919d2ede37ad7d",
		y:     "0x13e9b03b97dfa62ddd9979f86c6cab814f2f1557fa82a9d0317d2f8ab1fa355ceec2e2dd4cf8dc575b02d5aced1dec3c70cf105c9bc93a590425f588ca1ee86c0e5",
	},
	{
		curve: secg.Sect113r1(),
		x:     "0x1befca336ea60c4e294d6b55f0c8f",
		y:     "0x495efeb589c3da382cfce77cb298",
	},
	{
		curve: secg.Sect113r2(),
		x:     "0x16e19e6a126c65d4fa421a85dd6d",
		y:     "0x11fc01382ea55af83eb465fc0c790",
	},
	{
		curve: secg.Sect131r1(),
		x:     "0x1639b59e1c953c56db00f26e29d9410a9",
		y:     "0x2000a646bc8e0abc4cd63938b92d1019b",
	},
	{
		curve: secg.Sect131r2(),
		x:     "0x7b093f204e1086711220821608a57d940",
		y:     "0x64e0a21f6a3875cfcf0e0e404956e739d",
	},
	{
		curve: secg.Sect163k1(),
		x:     "0x2acfcfcc9a2af8e3f2828024f820033db20f69520",
		y:     "0x5729c47f915badc7b4c17df14e5804109ffecdfe4",
	},
	{
		curve: secg.Sect163r1(),
		x:     "0x48a0a8a89d53dfb023ea98cee93381c6715aa87d1",
		y:     "0x6be5460da1ad9ac2eff25554ddb5fe237bae5d412",
	},
	{
		curve: secg.Sect163r2(),
		x:     "0x634000577f86aa315009d6f9b906691f6edd691fe",
		y:     "0x401a3de0d6c2ec014e6fba5653587bd45dc2230be",
	},
	{
		curve: secg.Sect193r1(),
		x:     "0x17a1644d5a5ee5f7d38ffc105659d115d0fcb037ec5ebc8e1",
		y:     "0x1ea116683a89575d97f3be5c717a4924e4c9b0c5209a3b990",
	},
	{
		curve: secg.Sect193r2(),
		x:     "0x19edaee3d5d3685c6aa83c96bafddec3bc4882cb394fb109f",
		y:     "0x7d3cb0340de2a53cb86a54924f944666f1ed7322db41e618",
	},
	{
		curve: secg.Sect233k1(),
		x:     "0x4656e0aabbe341407715ca4a7fac287b41baa1f789c29bfa27e53a7a46",
		y:     "0xf79a7245fba513df787a64c618e97ebcc078638ebaaa562e9862bc00ce",
	},
	{
		curve: secg.Sect233r1(),
		x:     "0x80f50a330911bd753a76364595b9f0158c4d02a85cc0e3fb6ea0aef9ff",
		y:     "0x17a49033f12eb52675e98e6432cc27104bd5c42bcbe3daf76901c9b8743",
	},
	{
		curve: secg.Sect239k1(),
		x:     "0xc573319e44a381e6235a8201ecb27669cfbcb4c0c3098cd5cd989ca7c19",
		y:     "0x751bdd7ac5bee4ff25464e604d0c11e4cd1271de94b2211727cea4536157",
	},
	{
		curve: secg.Sect283k1(),
		x:     "0x15dccc30a8b1f5146412d51fec337741090321408aac521391ad36c5912e280124fe3b5",
		y:     "0x53fc9bed137312952ad97f6a98c4c7ac1b421635fbafe28898e9213d979d5b4d279f192",
	},
	{
		curve: secg.Sect283r1(),
		x:     "0xd257a925ba8bbf1a490a06a80d8338453a9a00eed2c51a90467a4283b3a4df9de2bc0b",
		y:     "0x22a7592959069fbbc245bee792106e995513d5f6837b90f291feb732b1cbe3427c8e585",
	},
	{
		curve: secg.Sect409k1(),
		x:     "0x15cdee83fc75049adc9ac4b259a4973fc82fe6c27ad22796b0992521eebfbae63aacd6cc7decd27453215a5c92a2eca614f2fa2",
		y:     "0x973314e9c9e2eb4cf9d70cfc9127619d5d190131a8c8638f96e859976d3b34db7ed3651bde3779a5d833a9d05952a7d4d06d16",
	},
	{
		curve: secg.Sect409r1(),
		x:     "0xd5f0e8b27d12d7a9dcea13a5cfb9dee62d63376e31f7666ba2ac2bf314b91420749ef549a17e5dc6815a7b044ff458c40c415",
		y:     "0x1db5b78d491e45cc58e9e44bd7e42537597b9aba85e2e3589f02d466ed31b816235f6d22679690002fcef2b5390f0de885e90be",
	},
	{
		curve: secg.Sect571k1(),
		x:     "0x287b0ccbb649860ccb56f10afea9090c8a05a351d2b70671084c563d37c6536b8be7b6130bfcd60e2111cd8a1283edf48970333c3906a61809d10bbfd4e016650ad4a749a68199a",
		y:     "0x2264fc0cb1b83968ff3f8f5689aeacd2b3cc9ce59ef83f0007e2da3045ac8ab2c0b43f4a2c9d2f29710cccee24286c3e4224614eba64f2f1629fd79168094130f31d6ce787cbd41",
	},
	{
		curve: secg.Sect571r1(),
		x:     "0x72d033e612ca6dd14c28f1f6689af9a97bba7fd88a25bae969dd1c91e75a9f680442dea747eab06e73b746911780505dab0e03149de396b1020fbaf55580cf4d6eb9738ce0d26f8",
		y:     "0x494ba50070ca0fc97e89f3ea55de5aed4d5bd139b3725618dfeb90152230aa53fa37b6e39baad54a77771f0df01bffee82fbb0bad45f2d5c89f704c6eba6722b1e4433638d87dda",
	},
	// -------- ANSI X9.62 --------
	{
		curve: x962.Prime192v1(),
		x:     "0x76e32a2557599e6edcd283201fb2b9aadfd0d359cbb263da",
		y:     "0x782c37e372ba4520aa62e0fed121d49ef3b543660cfd05fd",
	},
	{
		curve: x962.Prime192v2(),
		x:     "0x4aac8ec6e4ae0ff1763ba50ae85927ffddd89ad43397c057",
		y:     "0xbf2cabe23018a134064b62562067642b40c42634041f70f7",
	},
	{
		curve: x962.Prime192v3(),
		x:     "0x1e23fa48e7e0191db4aa4652d6d8b6fbfa4fbe1dbc03e7b2",
		y:     "0xb1caf485dd72a51660aa6bef908a5f4aa67b4f815e8dd38e",
	},
	{
		curve: x962.Prime239v1(),
		x:     "0x22dbc8d0ec84c7ec9706fe55f226e24f4152950e4bf28a2ec2e908186360",
		y:     "0x141ab1dc0de87873aa10719ed8ed1bf00a1680fa3c41879aacab9e85cde3",
	},
	{
		curve: x962.Prime239v2(),
		x:     "0x5fe418597fe277f121524b604387ad05adc9004de22195f7e9403a6a555a",
		y:     "0x2f62636c00ac6920808c5715078baa197481c0e86fd349005fa0d06617ee",
	},
	{
		curve: x962.Prime239v3(),
		x:     "0x311d5e1ea454cf69e6eaa3b0aa4a8979bd645ffd7f8c4638f8c2bb90b02b",
		y:     "0x2698353cf82b32f1bfe06f54955032bb81e7b71c28c3042bee6273312a11",
	},
	{
		curve: x962.Prime256v1(),
		x:     "0x5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c",
		y:     "0x8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032",
	},
	{
		curve: x962.C2pnb176w1(),
		x:     "0x3f7e0e081d337f91d61e8a6c18fa1cfde6803b798ec2",
		y:     "0x85f5b685bc627c4890df301307cc7ce630870c9cff5f",
	},
	{
		curve: x962.C2pnb163v1(),
		x:     "0x2781fe91116ef3c4c47c778e10476dc1b7fde9bc3",
		y:     "0x3730567f081522a704691be7c30037041e5368aa2",
	},
	{
		curve: x962.C2pnb163v2(),
		x:     "0x1570a9c65674d9d861a8bfaefadd1f59df714841",
		y:     "0x2d20342ee5385f17693b0b93ac1dfbf0ae350a383",
	},
	{
		curve: x962.C2pnb163v3(),
		x:     "0x22a62f28645337bb495adb027a5447332534a145",
		y:     "0x6c5cf3b65d53915909acd7540c0aec90570a59555",
	},
	{
		curve: x962.C2pnb208w1(),
		x:     "0x2535ee0eb309bdc74e7f0fd706d1a18cc4df732aad751d3e0e75",
		y:     "0xf1267157f24a378a0a07b732e719954fb70949832b3cf6aed969",
	},
	{
		curve: x962.C2tnb191v3(),
		x:     "0x57b67154b42c91cad83e58fc42a8d055cecd77b81be0587d",
		y:     "0x25a2adbc20ea6c178f80592fca5b037b5e70660b646c9faf",
	},
	{
		curve: x962.C2tnb191v2(),
		x:     "0x6f28de94b4718df6edc685792f80e26320b03637564faebc",
		y:     "0x6020020c688c9e79fe3dc667ddaac28626259150a5956ab4",
	},
	{
		curve: x962.C2tnb191v1(),
		x:     "0x1eb3277ca60411b75de873c305e3a630c4446aad26192bcd",
		y:     "0x66bd73150de6164db353e381a6dad3900b9f583abfbe4d05",
	},
	{
		curve: x962.C2tnb239v3(),
		x:     "0x4cf57b6d91d9821df17a07b653dfda33cb6c305b55c28cd13aacef9b27b7",
		y:     "0x72ee0654305bde3cde4b3454230f7548289a84867ba587820717e238eb34",
	},
	{
		curve: x962.C2tnb239v2(),
		x:     "0x1d73bdc2a73d9668949f091bafe69d6a6490bf9f587a60d14d63d0bd5945",
		y:     "0x7eddae40cef480cc1e9aa37e706928156303d2571cd8cbcb1d5fe2a476b0",
	},
	{
		curve: x962.C2tnb239v1(),
		x:     "0x2b147cfaea0df6e6717fc47f25c951133362bd490d51e75e03ca9273bbdb",
		y:     "0x233be214af69e0969159e9f4edd4934072e6b5975f0596683e67addff8c5",
	},
	{
		curve: x962.C2pnb272w1(),
		x:     "0x7df30611c8314ee1c8a22796c6eb134e58010dd2f509201ce33aa5a02e18899c983e",
		y:     "0xf55644b2834c6873109964383c5466bb58423d799751921080e09362c39a44863efc",
	},
	{
		curve: x962.C2pnb304w1(),
		x:     "0x995806569b4179fdf9cecdb386b16511d1a206f3edc94eb391e14ad7a2271c7f8293c561245a",
		y:     "0xaa672099b9e6c4d23feac72656652e71c8e72411711b9141ac2a4f9d48405fe489dc8c974d1",
	},
	{
		curve: x962.C2pnb368w1(),
		x:     "0xac443d730613eb69f6eebde5840baa5abbcb4b1795f9c253fceb52c1093731d046d16da08eea9387f7773d777fd1",
		y:     "0x866aee1c23a0c3e2ceee1874f89585dacb429195bc73d30d0ea0d44deea1a8fd62098908e2336a74496c40b0a674",
	},
	{
		curve: x962.C2tnb359v1(),
		x:     "0xc2db33bcea53dabc6e0c01a2ecd106403584c6993192e788e35032d23294d5559746610264eaee488395bb6e2",
		y:     "0x5f82b4c9f324aed8abac0da3937ed29f6c8108442892d8026d880280a91045de329772fa143844435e7e00d4b9",
	},
	{
		curve: x962.C2tnb431r1(),
		x:     "0x10a5b7db2486c2b28a392dff6b70a8ce86ffd9743fe9e6974b2daa280f1af803f540eb6c2cb0c45ab3e0f39fed3a9aabf287d25bab8b",
		y:     "0x402c52b1df1b0ffdd0b686e98e23074d395464d9200535c5dabbd7c0d9b77a1500f8b1a2b9ce38c06ed27d5937d6fe474af0812f02f6",
	},
	//{
	//	curve: x962.C2onb191v4(),
	//	x:     "0x59178300c278ac0f725dff5387f01630bb6af62e840566d7",
	//	y:     "0x379f28d4f00b00e56617ab6680938096fa398401984037ef",
	//},
	//{
	//	curve: x962.C2onb191v5(),
	//	x:     "0x55394e98bceab89b84a07390861ce919bd42dbeb5f0081d9",
	//	y:     "0x1d9db3ec16d777a30e3516d4337aaba354095531456c814c",
	//},
	//{
	//	curve: x962.C2onb239v4(),
	//	x:     "0x6a79a4943e7e827ba7258a1abf3a2ee4c82a8cd505b485bd46cbfc3405d5",
	//	y:     "0x5e55476274815330b5b27303e2edd0c7ced26d9a5b910a2ea60ba1a9b2f6",
	//},
	//{
	//	curve: x962.C2onb239v5(),
	//	x:     "0x6a77d40b7447581fcac835a764c49bc9f5dd9c5a248e5850b7b18bd1b24e",
	//	y:     "0x6befa304f7299281d4658fa179a1020527d00221ce8f130bb584fd26f434",
	//},
	// -------- ANSI X9.63 --------
	{
		curve: x963.Ansip224r1(),
		x:     "0xdf1b1d66a551d0d31eff822558b9d2cc75c2180279fe0d08fd896d04",
		y:     "0xa3f7f03cadd0be444c0aa56830130ddf77d317344e1af3591981a925",
	},
	{
		curve: x963.Ansip384r1(),
		x:     "0x77a41d4606ffa1464793c7e5fdc7d98cb9d3910202dcd06bea4f240d3566da6b408bbae5026580d02d7e5c70500c831",
		y:     "0xc995f7ca0b0c42837d0bbe9602a9fc998520b41c85115aa5f7684c0edc111eacc24abd6be4b5d298b65f28600a2f1df1",
	},
	{
		curve: x963.Ansip521r1(),
		x:     "0x1a73d352443de29195dd91d6a64b5959479b52a6e5b123d9ab9e5ad7a112d7a8dd1ad3f164a3a4832051da6bd16b59fe21baeb490862c32ea05a5919d2ede37ad7d",
		y:     "0x13e9b03b97dfa62ddd9979f86c6cab814f2f1557fa82a9d0317d2f8ab1fa355ceec2e2dd4cf8dc575b02d5aced1dec3c70cf105c9bc93a590425f588ca1ee86c0e5",
	},
	{
		curve: x963.Ansit163k1(),
		x:     "0x2acfcfcc9a2af8e3f2828024f820033db20f69520",
		y:     "0x5729c47f915badc7b4c17df14e5804109ffecdfe4",
	},
	{
		curve: x963.Ansit163r1(),
		x:     "0x48a0a8a89d53dfb023ea98cee93381c6715aa87d1",
		y:     "0x6be5460da1ad9ac2eff25554ddb5fe237bae5d412",
	},
	{
		curve: x963.Ansit163r2(),
		x:     "0x634000577f86aa315009d6f9b906691f6edd691fe",
		y:     "0x401a3de0d6c2ec014e6fba5653587bd45dc2230be",
	},
	{
		curve: x963.Ansit193r1(),
		x:     "0x17a1644d5a5ee5f7d38ffc105659d115d0fcb037ec5ebc8e1",
		y:     "0x1ea116683a89575d97f3be5c717a4924e4c9b0c5209a3b990",
	},
	{
		curve: x963.Ansit193r2(),
		x:     "0x19edaee3d5d3685c6aa83c96bafddec3bc4882cb394fb109f",
		y:     "0x7d3cb0340de2a53cb86a54924f944666f1ed7322db41e618",
	},
	{
		curve: x963.Ansit233k1(),
		x:     "0x4656e0aabbe341407715ca4a7fac287b41baa1f789c29bfa27e53a7a46",
		y:     "0xf79a7245fba513df787a64c618e97ebcc078638ebaaa562e9862bc00ce",
	},
	{
		curve: x963.Ansit233r1(),
		x:     "0x80f50a330911bd753a76364595b9f0158c4d02a85cc0e3fb6ea0aef9ff",
		y:     "0x17a49033f12eb52675e98e6432cc27104bd5c42bcbe3daf76901c9b8743",
	},
	{
		curve: x963.Ansit239k1(),
		x:     "0xc573319e44a381e6235a8201ecb27669cfbcb4c0c3098cd5cd989ca7c19",
		y:     "0x751bdd7ac5bee4ff25464e604d0c11e4cd1271de94b2211727cea4536157",
	},
	{
		curve: x963.Ansit283k1(),
		x:     "0x15dccc30a8b1f5146412d51fec337741090321408aac521391ad36c5912e280124fe3b5",
		y:     "0x53fc9bed137312952ad97f6a98c4c7ac1b421635fbafe28898e9213d979d5b4d279f192",
	},
	{
		curve: x963.Ansit283r1(),
		x:     "0xd257a925ba8bbf1a490a06a80d8338453a9a00eed2c51a90467a4283b3a4df9de2bc0b",
		y:     "0x22a7592959069fbbc245bee792106e995513d5f6837b90f291feb732b1cbe3427c8e585",
	},
	{
		curve: x963.Ansit409k1(),
		x:     "0x15cdee83fc75049adc9ac4b259a4973fc82fe6c27ad22796b0992521eebfbae63aacd6cc7decd27453215a5c92a2eca614f2fa2",
		y:     "0x973314e9c9e2eb4cf9d70cfc9127619d5d190131a8c8638f96e859976d3b34db7ed3651bde3779a5d833a9d05952a7d4d06d16",
	},
	{
		curve: x963.Ansit409r1(),
		x:     "0xd5f0e8b27d12d7a9dcea13a5cfb9dee62d63376e31f7666ba2ac2bf314b91420749ef549a17e5dc6815a7b044ff458c40c415",
		y:     "0x1db5b78d491e45cc58e9e44bd7e42537597b9aba85e2e3589f02d466ed31b816235f6d22679690002fcef2b5390f0de885e90be",
	},
	{
		curve: x963.Ansit571k1(),
		x:     "0x287b0ccbb649860ccb56f10afea9090c8a05a351d2b70671084c563d37c6536b8be7b6130bfcd60e2111cd8a1283edf48970333c3906a61809d10bbfd4e016650ad4a749a68199a",
		y:     "0x2264fc0cb1b83968ff3f8f5689aeacd2b3cc9ce59ef83f0007e2da3045ac8ab2c0b43f4a2c9d2f29710cccee24286c3e4224614eba64f2f1629fd79168094130f31d6ce787cbd41",
	},
	{
		curve: x963.Ansit571r1(),
		x:     "0x72d033e612ca6dd14c28f1f6689af9a97bba7fd88a25bae969dd1c91e75a9f680442dea747eab06e73b746911780505dab0e03149de396b1020fbaf55580cf4d6eb9738ce0d26f8",
		y:     "0x494ba50070ca0fc97e89f3ea55de5aed4d5bd139b3725618dfeb90152230aa53fa37b6e39baad54a77771f0df01bffee82fbb0bad45f2d5c89f704c6eba6722b1e4433638d87dda",
	},
}

func testDoubleAndAdd(curve elliptic.Curve, x1, y1, ex, ey *big.Int) bool {
	x, y := curve.Double(x1, y1)
	x, y = curve.Add(x, y, x1, y1)
	return x.Cmp(ex) == 0 && y.Cmp(ey) == 0
}

func TestDoubleAndAdd(t *testing.T) {
	for _, tc := range testvec3G {
		params := tc.curve.Params()
		Gx, Gy := params.Gx, params.Gy

		Ex := ecc.HexToBigInt(tc.x)
		Ey := ecc.HexToBigInt(tc.y)

		if !testDoubleAndAdd(tc.curve, Gx, Gy, Ex, Ey) {
			t.Errorf("%s Add(Double(G), G) != 3G", tc.curve.Params().Name)
		}
	}
}

func testScalarBaseMult(curve elliptic.Curve, k, ex, ey *big.Int) bool {
	x, y := curve.ScalarBaseMult(k.Bytes())
	return x.Cmp(ex) == 0 && y.Cmp(ey) == 0
}

func TestScalarBaseMult(t *testing.T) {
	three := big.NewInt(3)
	for _, tc := range testvec3G {
		Ex := ecc.HexToBigInt(tc.x)
		Ey := ecc.HexToBigInt(tc.y)

		if !testScalarBaseMult(tc.curve, three, Ex, Ey) {
			t.Errorf("%s ScalarBaseMult(3) != 3G", tc.curve.Params().Name)
		}
	}
}

func testScalarMult(curve elliptic.Curve, x1, y1, k, ex, ey *big.Int) bool {
	x, y := curve.ScalarMult(x1, y1, k.Bytes())
	return x.Cmp(ex) == 0 && y.Cmp(ey) == 0
}

func TestScalarMult(t *testing.T) {
	three := big.NewInt(3)
	for _, tc := range testvec3G {
		params := tc.curve.Params()
		Gx, Gy := params.Gx, params.Gy
		Ex := ecc.HexToBigInt(tc.x)
		Ey := ecc.HexToBigInt(tc.y)

		if !testScalarMult(tc.curve, Gx, Gy, three, Ex, Ey) {
			t.Errorf("%s ScalarMult(G, 3) != 3G", tc.curve.Params().Name)
		}
	}
}

func TestIsOnCurve(t *testing.T) {
	for _, tc := range testvec3G {
		Ex := ecc.HexToBigInt(tc.x)
		Ey := ecc.HexToBigInt(tc.y)
		ok := tc.curve.IsOnCurve(Ex, Ey)
		if ok != true {
			t.Errorf("%s IsOnCurve(%s, %s) = false", tc.curve.Params().Name, tc.x, tc.y)
		}
	}
}

func TestHasOID(t *testing.T) {
	for _, tc := range testvec3G {
		_, ok := tc.curve.(ecc.Curve)
		if !ok {
			t.Errorf("%s is not an ecc.Curve", tc.curve.Params().Name)
			continue
		}
	}
}

func TestSign(t *testing.T) {
	for _, tc := range testvec3G {
		priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("hello world")
		r, s, err := ecdsa.Sign(rand.Reader, priv, msg)
		if err != nil {
			t.Fatal(err)
		}
		if !ecdsa.Verify(&priv.PublicKey, msg, r, s) {
			t.Errorf("%s failed to verify signature", tc.curve.Params().Name)
		}
	}
}
