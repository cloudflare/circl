package sidh

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/dh/sidh/internal/common"
	. "github.com/cloudflare/circl/internal/test"
)

/* -------------------------------------------------------------------------
   Test data
   -------------------------------------------------------------------------*/

type sidhVec struct {
	id   uint8
	name string
	PkA  string
	PrA  string
	PkB  string
	PrB  string
}

var tdataSidh = map[uint8]sidhVec{
	Fp434: {
		id:   Fp434,
		name: "P-434",
		PrA:  "3A727E04EA9B7E2A766A6F846489E7E7B915263BCEED308BB10FC900",
		PrB:  "E37BFE55B43B32448F375903D8D226EC94ADBFEA1D2B3536EB987001",
		PkA: "9E668D1E6750ED4B91EE052C32839CA9DD2E56D52BC24DECC950AAAD" +
			"24CEED3F9049C77FE80F0B9B01E7F8DAD7833EEC2286544D6380009C" +
			"379CDD3E7517CEF5E20EB01F8231D52FC30DC61D2F63FB357F85DC63" +
			"96E8A95DB9740BD3A972C8DB7901B31F074CD3E45345CA78F9008171" +
			"30E688A29A7CF0073B5C00FF2C65FBE776918EF9BD8E75B29EF7FAB7" +
			"91969B60B0C5B37A8992EDEF95FA7BAC40A95DAFE02E237301FEE9A7" +
			"A43FD0B73477E8035DD12B73FAFEF18D39904DDE3653A754F36BE188" +
			"8F6607C6A7951349A414352CF31A29F2C40302DB406C48018C905EB9" +
			"DC46AFBF42A9187A9BB9E51B587622A2862DC7D5CC598BF38ED6320F" +
			"B51D8697AD3D7A72ABCC32A393F0133DA8DF5E253D9E00B760B2DF34" +
			"2FCE974DCFE946CFE4727783531882800F9E5DD594D6D5A6275EEFEF" +
			"9713ED838F4A06BB34D7B8D46E0B385AAEA1C7963601",
		PkB: "C9F73E4497AAA3FDF9EB688135866A8A83934BA10E273B8CC3808CF0" +
			"C1F5FAB3E9BB295885881B73DEBC875670C0F51C4BB40DF5FEDE01B8" +
			"AF32D1BF10508B8C17B2734EB93B2B7F5D84A4A0F2F816E9E2C32AC2" +
			"53C0B6025B124D05A87A9E2A8567930F44BAA14219B941B6B400B4AE" +
			"D1D796DA12A5A9F0B8F3F5EE9DD43F64CB24A3B1719DF278ADF56B5F" +
			"3395187829DA2319DEABF6BBD6EDA244DE2B62CC5AC250C1009DD1CD" +
			"4712B0B37406612AD002B5E51A62B51AC9C0374D143ABBBD58275FAF" +
			"C4A5E959C54838C2D6D9FB43B7B2609061267B6A2E6C6D01D295C422" +
			"3E0D3D7A4CDCFB28A7818A737935279751A6DD8290FD498D1F6AD5F4" +
			"FFF6BDFA536713F509DCE8047252F1E7D0DD9FCC414C0070B5DCCE36" +
			"65A21A032D7FBE749181032183AFAD240B7E671E87FBBEC3A8CA4C11" +
			"AA7A9A23AC69AE2ACF54B664DECD27753D63508F1B02",
	},
	Fp503: {
		id:   Fp503,
		name: "P-503",
		PrA:  "D5B94224FA1AD1701EC277FDA83462D09E87181C2E583C5F09FD446A43F25103",
		PrB:  "FF0EF91753D71D83D912656856086007AD2CF3B2A979B2BD63E5313BFD276506",
		PkA: "FFB9A589DBB3975A20373F1AD3B449880E1DA47916FCD7C751A019AAA8E95A03" +
			"4ADA1AE8BFCF6FBF70F323713318E25315DE865B29C9124982594BF78CD61C09" +
			"B98C22307DFD4FC0958C58EC0D144828006E510FA4072D721B48D1A3CFEA02F6" +
			"062324FE1B68F457CF29BD4EB1FB68D0684EE69F53A3FAC327404341BB39365B" +
			"5DE885034C9A6DD6798CB08126183C696D0302730D489584AC8D6BCADF3AB4DE" +
			"FFC227D3B1701462DA15BF68EF2B07C44712DB5429B74063202F43DC0EA7919D" +
			"B95025B2B03E5A3EBF57FF37E21838CE8F5531F491315E576A260DC2F515DDF2" +
			"4DEDE54CA69737CE6442B4219CD472D9CCCF8AF12B5C5B23ACB9C22929924ABA" +
			"52C820932C82435518B920AFC43F2041263AE98D29E58B73F33A5DD42AAC7533" +
			"404B4AC2B83DD2C7BEA7676930B6007CC185C264672B75F5332C18429BBC7B0F" +
			"2EA3F746995A298E7443FFB0C1B27DCA7D19635064AF3B87938960587F56B724" +
			"C1EF1FF012B056D7301F8713295B7734563542D4259B8BEA260C",
		PkB: "AA3303F79FCE4855DE125B239D10BEC3B7082E55B08C769A9765F1BF41A31210" +
			"66382D6BF2857D85138CC17D69593B8FC7703D22C553FB077DFB3AC577CF1E55" +
			"2AED6DC0368123E01DDD70059A47E31E06423D2F697A3DA5D621EB5FF2A52EE7" +
			"CA7D3BD01B427AC14CB6099E03C6639A3BAC9B939297CEB10F276F93CF16A1EE" +
			"1B8085DE3DA037C911491B145B034A47B42A996A61C2313FEF166FD3665B0AE8" +
			"C201A268DA01AB52E4759ACCC1DD09685A17CDA5D44AF847931ABB221D62E241" +
			"2329394445ADFD662C77472A9268F40AB540177C0E6F1D59026E595C46FBED2F" +
			"703838C5F3D7A811B500237596C5E960AA1F2989C5F17DD60D8A752569DBF250" +
			"E01C63C9790D014CE05A9D8683814A320E30185E478AF9ABD761DADDA8DE7E3E" +
			"A53C224AC8313C176D14BD0F04AB09A9D0D0302ACBF768EB4DB03681EAE3BC10" +
			"21CAA429A1490AE1D6E0CA9D6BC4BCD14B1CFE694226D03E8731E9E0B3760877" +
			"7D56630B31298CC05B6FF6C1A08935312D8E95B8056AD7831A22",
	},
	Fp751: {
		id:   Fp751,
		name: "P-751",
		// PrA - Alice's Private Key: 2*randint(0,2^371)
		PrA: "B1937F2B009FD9F785C5AD899F5ED2FD064218C07A76798D1433336E093DF184CA0CAF6E7C92B320E89632A7765F0B",
		// PrB - Bob's Private Key: 3*randint(0,3^238)
		PrB: "54DB4380D4134E187F5793FA82A4F18B39CA2F8F1C145FFB040FC917E2F41542037FF227F3A4AAFB17A6983AA88B4403",
		PkA: "2B53BB7C002A9D18B077D068C38353ADFD57A3CA0E431D92CCB8060D41A83A09" +
			"C1500BEE63FB07DA1DBEDB4AF145F22C2D8152B07B7E124F06643C7AB5B1C48D" +
			"581FC4C6FB7FC165F6E02F40B47D81400B84B6288DEAB38DE795B51486430974" +
			"788377770D46B0ABC1F3F7C3647A0E38ACED475EA8EE990F3C5A7668452478C1" +
			"975993E126B405E476AD6A10E9DD4E135ADA910BE41A8F93331268791F7B958A" +
			"0888052D1CF7B9128058A258002F22AC48E2C296E3935033139D336FDEB33E9B" +
			"8713663B1705B566AC4F4455FD0E710A5236C18011EA971DDD18633F9022C432" +
			"B225EC401FCD4C233B8BF91BE5944D1A657516CE4B844D0BC6049478046B60B6" +
			"BE163E41CCE743054806B13FAC0A1FA393C866D74A5A93A938209287324FAB46" +
			"295F5B271C9D8CFEE17868599202D7AEF1A67EBE2FA2A27AD9E0991CEDEE270D" +
			"1E7639425D94A0F0A2EFDE90B86D5D7F03F3CF97D30415CAA661F865ADB788E6" +
			"3F79EE2FE8637D9DCAF3BCD5C42AE499688048BBB49F216B4714675FD87F7CCC" +
			"37A0C2EA56BB53675584F7648BA052F963C35387ECC4DDED4F8076934FF32D5D" +
			"77B5D3C57553757A4CB9588C4575D4CC4CA8280370041A6FF03007C31D0712E8" +
			"327CC5BC9885F896904FAB4EE167745260D331C3E85E8A32FCCD23093F2C55A9" +
			"EA8D7BECEFC3564D3C3D4CE585B62785773B2228742185C97D6F51CD3E3CF885" +
			"5CF37F305734E97A86479580FDB9983DDCAE9D0F1B125523DB2FE58339240A58" +
			"131D0EFD14A560A6F7EDE774F6C3C54F46DD0830",
		PkB: "E93E4E2B0E7348C088FD91F8E3B17CC52B55C5E8933B6D00B3757E5347C5A0AE" +
			"5F1A6051C32FB20A41013A244484C8D0501B6A3516A634581E08C907F29D651C" +
			"BCC5B6CA6BAC4DCC980CD36155B60A2108134D3F78ED19ADA2B8B20184302FD7" +
			"47E096B01ABB33CB76B115D673B00F76913281CF7A0B44FF5CF1A256B8138FE6" +
			"77AB8D22FEBBCB10EB46E442D0AD96A126DD24E941280C7AB3F9FAC2832A149C" +
			"AD93D221EDCB406303F5A1B38F43F310244D766239A7F4D89EED4C6FD272BC4F" +
			"F7C4E34F3E5E77BFF59D6FE5C0D3937F574ABE81C2FC1FEDD98F43323F8F2D7C" +
			"154DCEBF410FCF698A4E6506D6FD6E4A861395F75698C810A527E00ADC118C90" +
			"9CDE7729B24C6E7DE9C92CFB592CB9A4BAC54DB468AA52724452CC7A7B40509B" +
			"B7894ACCF2C7933537FD52DB312D7FBC4FDE01AC2350CD25ABDD5E6F3AEF87BA" +
			"1BE23691544EB6A4F8FA9CF2BE70B9665EA479B44DC3C61D4651CDDB53656B6F" +
			"3A2D139EC6BE8550B8A623CCA30EB5374F70C67A932712002006F3D73190384F" +
			"6D3BEC9DB9F46E9B7AE2891E615752E74DC112579CF43283E8B6EBEF4C802BD6" +
			"700A97B9739E8694B48D8CB9C8ABBC915A834FF1DBF2C823B3E156D0A415C558" +
			"71B719BD9DD215F57C8D19A6B4F8CD93283D6EBD135347DAAF4F20C54D24017F" +
			"5E6AF400AB6DC98AD2D5810E59360DF64503599FAF6FBAB720CC557DEEF0F528" +
			"249DEB530C8F310465E0BE2B4041C24DAF783BC4EE71D27C760FA7CFD4A9A691" +
			"70BCBA465CA242961671DF0C53A8112CCD708D58",
	},
}

/* -------------------------------------------------------------------------
   Helpers
   -------------------------------------------------------------------------*/
// Converts string to private key.
func convToPrv(s string, v KeyVariant, id uint8) *PrivateKey {
	key := NewPrivateKey(id, v)
	hex, e := hex.DecodeString(s)
	if e != nil {
		panic("non-hex number provided")
	}
	e = key.Import(hex)
	if e != nil {
		panic("Can't import private key")
	}
	return key
}

// Converts string to public key.
func convToPub(s string, v KeyVariant, id uint8) *PublicKey {
	key := NewPublicKey(id, v)
	hex, e := hex.DecodeString(s)
	if e != nil {
		panic("non-hex number provided")
	}
	e = key.Import(hex)
	if e != nil {
		panic("Can't import public key")
	}
	return key
}

/* Unit tests */

func testKeygen(t *testing.T, v sidhVec) {
	pubA := NewPublicKey(v.id, KeyVariantSidhA)
	pubB := NewPublicKey(v.id, KeyVariantSidhB)
	alicePrivate := convToPrv(v.PrA, KeyVariantSidhA, v.id)
	bobPrivate := convToPrv(v.PrB, KeyVariantSidhB, v.id)
	expPubA := convToPub(v.PkA, KeyVariantSidhA, v.id)
	expPubB := convToPub(v.PkB, KeyVariantSidhB, v.id)

	alicePrivate.GeneratePublicKey(pubA)
	bobPrivate.GeneratePublicKey(pubB)

	got := make([]byte, expPubA.Size())
	exp := make([]byte, expPubA.Size())
	pubA.Export(got)
	expPubA.Export(exp)
	if !bytes.Equal(got, exp) {
		t.Fatalf("unexpected value of public key A\ngot [%X]\nexp [%X]", got, exp)
	}

	got = make([]byte, expPubB.Size())
	exp = make([]byte, expPubB.Size())
	pubB.Export(got)
	expPubB.Export(exp)
	if !bytes.Equal(got, exp) {
		t.Fatalf("unexpected value of public key B\ngot [%X]\nexp [%X]", got, exp)
	}
}

func testRoundtrip(t *testing.T, v sidhVec) {
	var err error
	pubA := NewPublicKey(v.id, KeyVariantSidhA)
	pubB := NewPublicKey(v.id, KeyVariantSidhB)
	prvA := NewPrivateKey(v.id, KeyVariantSidhA)
	prvB := NewPrivateKey(v.id, KeyVariantSidhB)
	s1 := make([]byte, common.Params(v.id).SharedSecretSize)
	s2 := make([]byte, common.Params(v.id).SharedSecretSize)

	// Generate private keys
	err = prvA.Generate(rand.Reader)
	CheckNoErr(t, err, "key generation failed")
	err = prvB.Generate(rand.Reader)
	CheckNoErr(t, err, "key generation failed")

	// Generate public keys
	prvA.GeneratePublicKey(pubA)
	prvB.GeneratePublicKey(pubB)

	// Derive shared secret
	prvB.DeriveSecret(s1, pubA)
	prvA.DeriveSecret(s2, pubB)

	if !bytes.Equal(s1[:], s2[:]) {
		t.Fatalf("Two shared keys do not match:\ns1 [%X]\ns2 [%X]", s1, s2)
	}
}

func testKeyAgreement(t *testing.T, v sidhVec) {
	var err error
	s1 := make([]byte, common.Params(v.id).SharedSecretSize)
	s2 := make([]byte, common.Params(v.id).SharedSecretSize)

	// KeyPairs
	alicePublic := convToPub(v.PkA, KeyVariantSidhA, v.id)
	bobPublic := convToPub(v.PkB, KeyVariantSidhB, v.id)
	alicePrivate := convToPrv(v.PrA, KeyVariantSidhA, v.id)
	bobPrivate := convToPrv(v.PrB, KeyVariantSidhB, v.id)

	// Do actual test
	bobPrivate.DeriveSecret(s1, alicePublic)
	alicePrivate.DeriveSecret(s2, bobPublic)

	if !bytes.Equal(s1[:], s2[:]) {
		t.Fatalf("two shared keys do not match\ngot [%X]\nexp [%X]", s1, s2)
	}

	// Negative case
	dec, err := hex.DecodeString(v.PkA)
	CheckNoErr(t, err, "decoding failed")

	dec[0] = ^dec[0]
	err = alicePublic.Import(dec)
	CheckNoErr(t, err, "import failed")
	bobPrivate.DeriveSecret(s1, alicePublic)
	alicePrivate.DeriveSecret(s2, bobPublic)
	if bytes.Equal(s1[:], s2[:]) {
		t.Fatalf("DeriveSecret produces wrong results. The two shared keys match, but they shouldn't")
	}
}

func testImportExport(t *testing.T, v sidhVec) {
	var err error
	a := NewPublicKey(v.id, KeyVariantSidhA)
	b := NewPublicKey(v.id, KeyVariantSidhB)

	// Import keys
	aHex, err := hex.DecodeString(v.PkA)
	CheckNoErr(t, err, "invalid hex-number provided")

	err = a.Import(aHex)
	CheckNoErr(t, err, "import failed")

	bHex, err := hex.DecodeString(v.PkB)
	CheckNoErr(t, err, "invalid hex-number provided")

	err = b.Import(bHex)
	CheckNoErr(t, err, "import failed")

	aBytes := make([]byte, a.Size())
	bBytes := make([]byte, b.Size())
	a.Export(aBytes)
	b.Export(bBytes)

	// Export and check if same
	if !bytes.Equal(bBytes, bHex) || !bytes.Equal(aBytes, aHex) {
		t.Fatalf("export/import failed")
	}

	if (len(bBytes) != b.Size()) || (len(aBytes) != a.Size()) {
		t.Fatalf("wrong size of exported keys")
	}

	// Ensure that public key is unchanged after it is exported
	aBytes2 := make([]byte, a.Size())
	bBytes2 := make([]byte, b.Size())
	a.Export(aBytes2)
	b.Export(bBytes2)
	if !bytes.Equal(aBytes, aBytes2) || !bytes.Equal(bBytes, bBytes2) {
		t.Fatalf("Second export doesn't match first export")
	}
}

func testPrivateKeyBelowMax(t *testing.T, vec sidhVec) {
	for variant, keySz := range map[KeyVariant]*common.DomainParams{
		KeyVariantSidhA: &common.Params(vec.id).A,
		KeyVariantSidhB: &common.Params(vec.id).B,
	} {
		func(v KeyVariant, dp *common.DomainParams) {
			blen := int(dp.SecretByteLen)
			prv := NewPrivateKey(vec.id, v)
			secretBytes := make([]byte, prv.Size())

			// Calculate either (2^e2 - 1) or (2^s - 1); where s=ceil(log_2(3^e3)))
			maxSecretVal := big.NewInt(int64(dp.SecretBitLen))
			maxSecretVal.Exp(big.NewInt(int64(2)), maxSecretVal, nil)
			maxSecretVal.Sub(maxSecretVal, big.NewInt(1))

			// Do same test 1000 times
			for i := 0; i < 1000; i++ {
				err := prv.Generate(rand.Reader)
				CheckNoErr(t, err, "Private key generation")

				// Convert to big-endian, as that's what expected by (*Int)SetBytes()
				prv.Export(secretBytes)
				for i := 0; i < blen/2; i++ {
					tmp := secretBytes[i] ^ secretBytes[blen-i-1]
					secretBytes[i] = tmp ^ secretBytes[i]
					secretBytes[blen-i-1] = tmp ^ secretBytes[blen-i-1]
				}
				prvBig := new(big.Int).SetBytes(secretBytes)
				// Check if generated key is bigger then acceptable
				if prvBig.Cmp(maxSecretVal) == 1 {
					t.Error("Generated private key is wrong")
				}
			}
		}(variant, keySz)
	}
}

func TestKeyAgreementP751_AliceEvenNumber(t *testing.T) {
	// even alice
	v := tdataSidh[Fp751]
	v.PkA = "FDED78E9F490CB518BD6357E18FEEB63FFEFEBE907338B3ABCA74A7E590DBF79" +
		"0C732AB9E3778244608CD563064BDF6AAEF511CEAF07C702309ADAA7EBEBC6B3" +
		"D7B00F5C02FB2FEDA763B2D695FD27F93F45D3AC58C2F0524A942D6DE407B651" +
		"1854A1D974F11A8686CF8AD675A081F4B668F3C6617029AA33FD597C8910AB37" +
		"F71DBE004A3FF8442C4B65DE51201DFAE6F9DC20FDE5B998D19C23589437229D" +
		"724B4378602321F247276E7B4E441383C9BE6D277A127362D9C9FB68A41C5F5B" +
		"9D2BA63FA790D62315DECF5049F0476A43D30BC1E8A36047C8EE0DA9E0A3937E" +
		"BDF52A91BC53266A82CBF2CEAB227CB6D5075B486679CA7701F6F35C53499B45" +
		"A451CE37C57B9BB1276142F495B83D987BD4B62E78E3084DCF3EB906D19DFA8F" +
		"819DFC7FDF104C1A01CCF8D933B91EBD72CDE83A502B1FB0A5DF782BC7085766" +
		"AE795123903A2D30F0F79073D27CF71BA4C9D3CA86512842AA8B5AEB729C78B1" +
		"E15392E20A6043C05F88F6F412C3C9FE14F8FAAE8B8482514822162F93E81615" +
		"BDD77363F872D0506FFDC1809C165A5C8A19F8EA0254D73E08202A6FF3AF43CF" +
		"A7EC9B137AE003A19440DCE2EF3CFC99080F75E683AF6D0E25DF55C60B2A8013" +
		"FA3D59828D31C2360DF83E202FB48AFAA65AF7279137E827B80E761FA49B842A" +
		"A70FD4E77B284A14B8E28C8B11B389E1160DD9877C8D5A5A1471E605F1848369" +
		"3F7578B3733DDEE117227E35B1765FEBB765B340A084E8D99176C0837099C864" +
		"C71C864842D3E9B58CB870AD45F3B6BE476FEB6D"
	v.PrA = "C09957CC83045FB4C3726384D784476ACB6FFD92E5B15B3C2D451BA063F1BD4CE" +
		"D8FBCF682A98DD0954D37BCAF730F"
	testKeyAgreement(t, v)
}

/* -------------------------------------------------------------------------
   Wrappers for 'testing' SIDH
   -------------------------------------------------------------------------*/

func testSidhVec(t *testing.T, m *map[uint8]sidhVec, f func(t *testing.T, v sidhVec)) {
	for i := range *m {
		v := (*m)[i]
		t.Run(v.name, func(t *testing.T) { f(t, v) })
	}
}
func TestKeygen(t *testing.T)             { testSidhVec(t, &tdataSidh, testKeygen) }
func TestRoundtrip(t *testing.T)          { testSidhVec(t, &tdataSidh, testRoundtrip) }
func TestImportExport(t *testing.T)       { testSidhVec(t, &tdataSidh, testImportExport) }
func TestKeyAgreement(t *testing.T)       { testSidhVec(t, &tdataSidh, testKeyAgreement) }
func TestPrivateKeyBelowMax(t *testing.T) { testSidhVec(t, &tdataSidh, testPrivateKeyBelowMax) }

/* -------------------------------------------------------------------------
   Benchmarking
   -------------------------------------------------------------------------*/

func BenchmarkSidhKeyAgreementP751(b *testing.B) {
	// KeyPairs
	alicePublic := convToPub(tdataSidh[Fp751].PkA, KeyVariantSidhA, Fp751)
	bobPublic := convToPub(tdataSidh[Fp751].PkB, KeyVariantSidhB, Fp751)
	alicePrivate := convToPrv(tdataSidh[Fp751].PrA, KeyVariantSidhA, Fp751)
	bobPrivate := convToPrv(tdataSidh[Fp751].PrB, KeyVariantSidhB, Fp751)
	var ss [2 * 94]byte

	for i := 0; i < b.N; i++ {
		// Derive shared secret
		bobPrivate.DeriveSecret(ss[:], alicePublic)
		alicePrivate.DeriveSecret(ss[:], bobPublic)
	}
}

func BenchmarkSidhKeyAgreementP503(b *testing.B) {
	// KeyPairs
	alicePublic := convToPub(tdataSidh[Fp503].PkA, KeyVariantSidhA, Fp503)
	bobPublic := convToPub(tdataSidh[Fp503].PkB, KeyVariantSidhB, Fp503)
	alicePrivate := convToPrv(tdataSidh[Fp503].PrA, KeyVariantSidhA, Fp503)
	bobPrivate := convToPrv(tdataSidh[Fp503].PrB, KeyVariantSidhB, Fp503)
	var ss [2 * 63]byte

	for i := 0; i < b.N; i++ {
		// Derive shared secret
		bobPrivate.DeriveSecret(ss[:], alicePublic)
		alicePrivate.DeriveSecret(ss[:], bobPublic)
	}
}

func BenchmarkSidhKeyAgreementP434(b *testing.B) {
	// KeyPairs
	alicePublic := convToPub(tdataSidh[Fp434].PkA, KeyVariantSidhA, Fp434)
	bobPublic := convToPub(tdataSidh[Fp434].PkB, KeyVariantSidhB, Fp434)
	alicePrivate := convToPrv(tdataSidh[Fp434].PrA, KeyVariantSidhA, Fp434)
	bobPrivate := convToPrv(tdataSidh[Fp434].PrB, KeyVariantSidhB, Fp434)
	var ss [2 * 63]byte

	for i := 0; i < b.N; i++ {
		// Derive shared secret
		bobPrivate.DeriveSecret(ss[:], alicePublic)
		alicePrivate.DeriveSecret(ss[:], bobPublic)
	}
}

func BenchmarkAliceKeyGenPrvP751(b *testing.B) {
	prv := NewPrivateKey(Fp751, KeyVariantSidhA)
	for n := 0; n < b.N; n++ {
		_ = prv.Generate(rand.Reader)
	}
}

func BenchmarkAliceKeyGenPrvP503(b *testing.B) {
	prv := NewPrivateKey(Fp503, KeyVariantSidhA)
	for n := 0; n < b.N; n++ {
		_ = prv.Generate(rand.Reader)
	}
}

func BenchmarkAliceKeyGenPrvP434(b *testing.B) {
	prv := NewPrivateKey(Fp434, KeyVariantSidhA)
	for n := 0; n < b.N; n++ {
		_ = prv.Generate(rand.Reader)
	}
}

func BenchmarkBobKeyGenPrvP751(b *testing.B) {
	prv := NewPrivateKey(Fp751, KeyVariantSidhB)
	for n := 0; n < b.N; n++ {
		_ = prv.Generate(rand.Reader)
	}
}

func BenchmarkBobKeyGenPrvP503(b *testing.B) {
	prv := NewPrivateKey(Fp503, KeyVariantSidhB)
	for n := 0; n < b.N; n++ {
		_ = prv.Generate(rand.Reader)
	}
}

func BenchmarkBobKeyGenPrvP434(b *testing.B) {
	prv := NewPrivateKey(Fp434, KeyVariantSidhB)
	for n := 0; n < b.N; n++ {
		_ = prv.Generate(rand.Reader)
	}
}

func BenchmarkAliceKeyGenPubP751(b *testing.B) {
	prv := NewPrivateKey(Fp751, KeyVariantSidhA)
	pub := NewPublicKey(Fp751, KeyVariantSidhA)
	_ = prv.Generate(rand.Reader)
	for n := 0; n < b.N; n++ {
		prv.GeneratePublicKey(pub)
	}
}

func BenchmarkAliceKeyGenPubP503(b *testing.B) {
	prv := NewPrivateKey(Fp503, KeyVariantSidhA)
	pub := NewPublicKey(Fp503, KeyVariantSidhA)
	_ = prv.Generate(rand.Reader)
	for n := 0; n < b.N; n++ {
		prv.GeneratePublicKey(pub)
	}
}

func BenchmarkAliceKeyGenPubP434(b *testing.B) {
	prv := NewPrivateKey(Fp434, KeyVariantSidhA)
	pub := NewPublicKey(Fp434, KeyVariantSidhA)
	_ = prv.Generate(rand.Reader)
	for n := 0; n < b.N; n++ {
		prv.GeneratePublicKey(pub)
	}
}

func BenchmarkBobKeyGenPubP751(b *testing.B) {
	prv := NewPrivateKey(Fp751, KeyVariantSidhB)
	pub := NewPublicKey(Fp751, KeyVariantSidhB)
	_ = prv.Generate(rand.Reader)
	for n := 0; n < b.N; n++ {
		prv.GeneratePublicKey(pub)
	}
}

func BenchmarkBobKeyGenPubP503(b *testing.B) {
	prv := NewPrivateKey(Fp503, KeyVariantSidhB)
	pub := NewPublicKey(Fp503, KeyVariantSidhB)
	_ = prv.Generate(rand.Reader)
	for n := 0; n < b.N; n++ {
		prv.GeneratePublicKey(pub)
	}
}

func BenchmarkBobKeyGenPubP434(b *testing.B) {
	prv := NewPrivateKey(Fp434, KeyVariantSidhB)
	pub := NewPublicKey(Fp434, KeyVariantSidhB)
	_ = prv.Generate(rand.Reader)
	for n := 0; n < b.N; n++ {
		prv.GeneratePublicKey(pub)
	}
}

func BenchmarkSharedSecretAliceP751(b *testing.B) {
	aPr := convToPrv(tdataSidh[Fp751].PrA, KeyVariantSidhA, Fp751)
	bPk := convToPub(tdataSidh[Fp751].PkB, KeyVariantSidhB, Fp751)
	var ss [2 * 94]byte
	for n := 0; n < b.N; n++ {
		aPr.DeriveSecret(ss[:], bPk)
	}
}

func BenchmarkSharedSecretAliceP503(b *testing.B) {
	aPr := convToPrv(tdataSidh[Fp503].PrA, KeyVariantSidhA, Fp503)
	bPk := convToPub(tdataSidh[Fp503].PkB, KeyVariantSidhB, Fp503)
	var ss [2 * 63]byte
	for n := 0; n < b.N; n++ {
		aPr.DeriveSecret(ss[:], bPk)
	}
}

func BenchmarkSharedSecretAliceP434(b *testing.B) {
	aPr := convToPrv(tdataSidh[Fp434].PrA, KeyVariantSidhA, Fp434)
	bPk := convToPub(tdataSidh[Fp434].PkB, KeyVariantSidhB, Fp434)
	var ss [2 * 63]byte
	for n := 0; n < b.N; n++ {
		aPr.DeriveSecret(ss[:], bPk)
	}
}

func BenchmarkSharedSecretBobP751(b *testing.B) {
	// m_B = 3*randint(0,3^238)
	aPk := convToPub(tdataSidh[Fp751].PkA, KeyVariantSidhA, Fp751)
	bPr := convToPrv(tdataSidh[Fp751].PrB, KeyVariantSidhB, Fp751)
	var ss [2 * 94]byte
	for n := 0; n < b.N; n++ {
		bPr.DeriveSecret(ss[:], aPk)
	}
}

func BenchmarkSharedSecretBobP503(b *testing.B) {
	// m_B = 3*randint(0,3^238)
	aPk := convToPub(tdataSidh[Fp503].PkA, KeyVariantSidhA, Fp503)
	bPr := convToPrv(tdataSidh[Fp503].PrB, KeyVariantSidhB, Fp503)
	var ss [2 * 63]byte
	for n := 0; n < b.N; n++ {
		bPr.DeriveSecret(ss[:], aPk)
	}
}

func BenchmarkSharedSecretBobP434(b *testing.B) {
	// m_B = 3*randint(0,3^238)
	aPk := convToPub(tdataSidh[Fp434].PkA, KeyVariantSidhA, Fp434)
	bPr := convToPrv(tdataSidh[Fp434].PrB, KeyVariantSidhB, Fp434)
	var ss [2 * 63]byte
	for n := 0; n < b.N; n++ {
		bPr.DeriveSecret(ss[:], aPk)
	}
}

// Examples

func ExamplePrivateKey() {
	// import "github.com/cloudflare/circl/dh/sidh"

	// Allice's key pair
	prvA := NewPrivateKey(Fp503, KeyVariantSidhA)
	pubA := NewPublicKey(Fp503, KeyVariantSidhA)
	// Bob's key pair
	prvB := NewPrivateKey(Fp503, KeyVariantSidhB)
	pubB := NewPublicKey(Fp503, KeyVariantSidhB)
	// Generate keypair for Allice
	err := prvA.Generate(rand.Reader)
	if err != nil {
		fmt.Print(err)
	}
	prvA.GeneratePublicKey(pubA)
	// Generate keypair for Bob
	err = prvB.Generate(rand.Reader)
	if err != nil {
		fmt.Print(err)
	}
	prvB.GeneratePublicKey(pubB)
	// Buffers storing shared secret
	ssA := make([]byte, prvA.SharedSecretSize())
	ssB := make([]byte, prvA.SharedSecretSize())
	// Allice calculates shared secret with hers private
	// key and Bob's public key
	prvA.DeriveSecret(ssA[:], pubB)
	// Bob calculates shared secret with hers private
	// key and Allice's public key
	prvB.DeriveSecret(ssB[:], pubA)
	// Check if ssA == ssB
	fmt.Printf("%t\n", bytes.Equal(ssA, ssB))
	// Output:
	// true
}
