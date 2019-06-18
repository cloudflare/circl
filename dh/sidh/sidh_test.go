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
	Fp503: {
		id:   Fp503,
		name: "P-503",
		PrA:  "B0AD510708F4ABCF3E0D97DC2F2FF112D9D2AAE49D97FFD1E4267F21C6E71C03",
		PrB:  "A885A8B889520A6DBAD9FB33365E5B77FDED629440A16A533F259A510F63A822",
		PkA: "A6BADBA04518A924B20046B59AC197DCDF0EA48014C9E228C4994CCA432F360E" +
			"2D527AFB06CA7C96EE5CEE19BAD53BF9218A3961CAD7EC092BD8D9EBB22A3D51" +
			"33008895A3F1F6A023F91E0FE06A00A622FD6335DAC107F8EC4283DC2632F080" +
			"4E64B390DAD8A2572F1947C67FDF4F8787D140CE2C6B24E752DA9A195040EDFA" +
			"C27333FAE97DBDEB41DA9EEB2DB067AE7DA8C58C0EF57AEFC18A3D6BD0576FF2" +
			"F1CFCAEC50C958331BF631F3D2E769790C7B6DF282B74BBC02998AD10F291D47" +
			"C5A762FF84253D3B3278BDF20C8D4D4AA317BE401B884E26A1F02C7308AADB68" +
			"20EBDB0D339F5A63346F3B40CACED72F544DAF51566C6E807D0E6E1E38514342" +
			"432661DC9564DA07548570E256688CD9E8060D8775F95D501886D958588CACA0" +
			"9F2D2AE1913F996E76AF63E31A179A7A7D2A46EDA03B2BCCF9020A5AA15F9A28" +
			"9340B33F3AE7F97360D45F8AE1B9DD48779A57E8C45B50A02C00349CD1C58C55" +
			"1D68BC2A75EAFED944E8C599C288037181E997471352E24C952B",
		PkB: "244AF1F367C2C33912750A98497CC8214BC195BD52BD76513D32ACE4B75E31F0" +
			"281755C265F5565C74E3C04182B9C244071859C8588CC7F09547CEFF8F7705D2" +
			"60CE87D6BFF914EE7DBE4B9AF051CA420062EEBDF043AF58184495026949B068" +
			"98A47046BFAE8DF3B447746184AF550553BB5D266D6E1967ACA33CAC5F399F90" +
			"360D70867F2C71EF6F94FF915C7DA8BC9549FB7656E691DAEFC93CF56876E482" +
			"CA2F8BE2D6CDCC374C31AD8833CABE997CC92305F38497BEC4DFD1821B004FEC" +
			"E16448F9A24F965EFE409A8939EEA671633D9FFCF961283E59B8834BDF7EDDB3" +
			"05D6275B61DA6692325432A0BAA074FC7C1F51E76208AB193A57520D40A76334" +
			"EE5712BDC3E1EFB6103966F2329EDFF63082C4DFCDF6BE1C5A048630B81871B8" +
			"83B735748A8FD4E2D9530C272163AB18105B10015CA7456202FE1C9B92CEB167" +
			"5EAE1132E582C88E47ED87B363D45F05BEA714D5E9933D7AF4071CBB5D49008F" +
			"3E3DAD7DFF935EE509D5DE561842B678CCEB133D62E270E9AC3E",
	},
	Fp751: {
		id:   Fp751,
		name: "P-751",
		// PrA - Alice's Private Key: 2*randint(0,2^371)
		PrA: "C09957CC83045FB4C3726384D784476ACB6FFD92E5B15B3C2D451BA063F1BD4CED8FBCF682A98DD0954D3" +
			"7BCAF730E",
		// PrB - Bob's Private Key: 3*randint(0,3^238)
		PrB: "393E8510E78A16D2DC1AACA9C9D17E7E78DB630881D8599C7040D05BB5557ECAE8165C45D5366ECB37B00" +
			"969740AF201",
		PkA: "74D8EF08CB74EC99BF08B6FBE4FB3D048873B67F018E44988B9D70C564D058401D20E093C7DF0C66F022C" +
			"823E5139D2EA0EE137804B4820E950B046A90B0597759A0B6A197C56270128EA089FA1A2007DDE3430B37" +
			"A3E6350BD47B7F513863741C125FA63DEDAFC475C13DB59E533055B7CBE4B2F32672DF2DF97E03E29617B" +
			"0E9B6A35B58ABB26527A721142701EB147C7050E1D9125DA577B08CD51C8BB50627B8B47FACFC9C7C07DD" +
			"00DD75115DD83719FD5F96115DED23ECAA50B1044C6BF3F27442DA284BA4A272D850F414FB185801BF2EF" +
			"7E628EDB5643E35694B992CF30A2C5120CAF9434F09ACFCA3645B3FFC3A308901FAC7B8955FD5C98576AE" +
			"FD03F5806CB7430F75B3431B75BEC080596ABCA26E637E6E8D4C25175A8C052C9CBE77900A863F83FAB00" +
			"95B32D9C3858EF8A35B9F163D429E71DBA47539EB4791D117FE39DDE94EA7801A42DB12D84DE4740ACF51" +
			"CD7C32BB854569D7D94E11E69D9663CC7ED02E78CF48F4069DF3D3E86198B307095C6B11D46C0DC849F9D" +
			"94C7693209E5B3848AFAA6DA6A8D73362D779CBC43515902ED2BCE3A748C537DE2FCF092FD3E91B790AF5" +
			"4E1092C5E5B89BE5BE23B955A52F769D97277EF69F820109042F28C316AC90AE69EB374C9280300B816E6" +
			"2494B2E01072D1CA96E4B284D2BE1368D6969744B614FACBC8C165864E26E33481D4FDC47B6E523954A25" +
			"C1A096A37CD23FB81AE64FB11BD0A439609F1CE40673B06DD96F698A910E935219D840F3D411EDFB00D98" +
			"065AB9868C32D3DA05FF415",
		PkB: "F6C260C4141E418457CB442E11F0F5558375437576E55D211D19EF83E2839E51D07A82765D8E7B6366FA7" +
			"0B56CDE3AD3B629ACF542A433369496EDA51EDFBE16EFA1B8DEE1CE46B37820ECBD0CD674AACD4F21FABC" +
			"2436651E3AF604356FF3EB2CA87976890E34A56FAEC9A2ACD9559B1BB67B69AC1A521342E1E787DA5D709" +
			"32B0F5842ECA1C99B269DB6C2ED8397F0FC49F114CF8B5AF327A698C0251575CDD1D67732668109A91A3B" +
			"FA5B47D413C7FAB8817FCBEBFE9BDD9C0B1F3B1934A7028A65233E8B58A92E7E9F66B68B2057ECBF7E44A" +
			"0EF6EFCC3C8AA5414E100FA0C24F7545324AD17062FC11377A2A4749DEE27E192460E099DBDA8E840EA11" +
			"AD9D5C83DF065AF77030E7FE18CE24CFC71D356B9B9601811B93676C12CB6B41747133D5259E7A20CC065" +
			"FAB99DF944FDB34ABB9A374F9E9CC8F9C186BD2181DC2771F69C02629C3E4801A7E7C21F6F3CFF7D257E2" +
			"257C88C015F0CC8DC0E7FB3373CF4ED6A786AB329E7F16895CA147AD91F6EAE1DFE38116580DF52381599" +
			"E4246278CB1848FE4A56ABF98652E9E7C2E681551A3D78FA033D932087D8B6567D779A56B726B153033D7" +
			"2231A1B5C16ED7DC4458308D6B64AF6723CC0F52C94E04C58FCA9739E890AA40CC05E22321F10129D2B59" +
			"1F317102034C109A56D711591E5B44C717CFC9C9B9461894767CAFA42D2B394194B03999C2A9EF48868F3" +
			"FB03D1A40F596613AF97F4ED7643A1C2D12692E959C6DEB8E72403ADC0E42204DBCE5056EEF0CC60B0C6E" +
			"83B8B55AC01F6C85644EE49",
	},
}

/* -------------------------------------------------------------------------
   Helpers
   -------------------------------------------------------------------------*/
// Converts string to private key
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

// Converts string to public key
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

/* -------------------------------------------------------------------------
   Unit tests
   -------------------------------------------------------------------------*/
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
	var e error
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
	dec, e := hex.DecodeString(v.PkA)
	if e != nil {
		t.FailNow()
	}
	dec[0] = ^dec[0]
	e = alicePublic.Import(dec)
	if e != nil {
		t.FailNow()
	}

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
		KeyVariantSidhB: &common.Params(vec.id).B} {

		func(v KeyVariant, dp *common.DomainParams) {
			var blen = int(dp.SecretByteLen)
			var prv = NewPrivateKey(vec.id, v)
			var secretBytes = make([]byte, prv.Size())

			// Calculate either (2^e2 - 1) or (2^s - 1); where s=ceil(log_2(3^e3)))
			maxSecertVal := big.NewInt(int64(dp.SecretBitLen))
			maxSecertVal.Exp(big.NewInt(int64(2)), maxSecertVal, nil)
			maxSecertVal.Sub(maxSecertVal, big.NewInt(1))

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
				if prvBig.Cmp(maxSecertVal) == 1 {
					t.Error("Generated private key is wrong")
				}
			}
		}(variant, keySz)
	}
}

func TestKeyAgreementP751_AliceEvenNumber(t *testing.T) {
	// even alice
	v := tdataSidh[Fp751]
	v.PkA = "8A2DE6FD963C475F7829B689C8B8306FC0917A39EBBC35CA171546269A85698FEC0379E2E1A3C567BE1B8EF5639F81F304889737E6CC444DBED4579DB204DC8C7928F5CBB1ECDD682A1B5C48C0DAF34208C06BF201BE4E6063B1BFDC42413B0537F8E76BEE645C1A24118301BAB17EB8D6E0F283BCB16EFB833E4BB3463953C93165A0DDAC55B385059F27FF7228486D0A733812C81C792BE9EC3A16A5DB0EB099EEA76AC0E59612251A3AD19F7CC567DA2AEBD7733171F48E471D17648692355164E27B515D2A47D7BA34B3B48A047BE7C09C4ABEE2FCC9ACA7396C8A8C9E73E29533FC7369094DFA7988778E55E53F309922C6E233F8F9C7936C3D29CEA640406FCA06450AA1978FF39F227BF06B1E072F1763447C6F513B23CDF3B0EC0379070AEE5A02D9AD8E0EB023461D631F4A9643A4C79921334945F6B33DDFC11D9703BD06B047B4DA404AB12EFD2C3A49E5C42D10DA063352748B21DE41C32A5693FE1C0DCAB111F4990CD58BECADB1892EE7A7E99C9DB4DA4E69C96E57138B99038BC9B877ECE75914EFB98DD08B9E4A2DCCB948A8F7D2F26678A9952BA0EFAB1E9CF6E51B557480DEC2BA30DE0FE4AFE30A6B30765EE75EF64F678316D81C72755AD2CFA0B8C7706B07BFA52FBC3DB84EF9E79796C0089305B1E13C78660779E0FF2A13820CE141104F976B1678990F85B2D3D2B89CD5BC4DD52603A5D24D3EFEDA44BAA0F38CDB75A220AF45EAB70F2799875D435CE50FC6315EDD4BB7AA7260AFD7CD0561B69B4FA3A817904322661C3108DA24"
	v.PrA = "C09957CC83045FB4C3726384D784476ACB6FFD92E5B15B3C2D451BA063F1BD4CED8FBCF682A98DD0954D37BCAF730F"
	testKeyAgreement(t, v)
}

/* -------------------------------------------------------------------------
   Wrappers for 'testing' SIDH
   -------------------------------------------------------------------------*/
func testSidhVec(t *testing.T, m *map[uint8]sidhVec, f func(t *testing.T, v sidhVec)) {
	for _, v := range *m {
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

func BenchmarkAliceKeyGenPrvP751(b *testing.B) {
	prv := NewPrivateKey(Fp751, KeyVariantSidhA)
	for n := 0; n < b.N; n++ {
		prv.Generate(rand.Reader)
	}
}

func BenchmarkAliceKeyGenPrvP503(b *testing.B) {
	prv := NewPrivateKey(Fp503, KeyVariantSidhA)
	for n := 0; n < b.N; n++ {
		prv.Generate(rand.Reader)
	}
}

func BenchmarkBobKeyGenPrvP751(b *testing.B) {
	prv := NewPrivateKey(Fp751, KeyVariantSidhB)
	for n := 0; n < b.N; n++ {
		prv.Generate(rand.Reader)
	}
}

func BenchmarkBobKeyGenPrvP503(b *testing.B) {
	prv := NewPrivateKey(Fp503, KeyVariantSidhB)
	for n := 0; n < b.N; n++ {
		prv.Generate(rand.Reader)
	}
}

func BenchmarkAliceKeyGenPubP751(b *testing.B) {
	prv := NewPrivateKey(Fp751, KeyVariantSidhA)
	pub := NewPublicKey(Fp751, KeyVariantSidhA)
	prv.Generate(rand.Reader)
	for n := 0; n < b.N; n++ {
		prv.GeneratePublicKey(pub)
	}
}

func BenchmarkAliceKeyGenPubP503(b *testing.B) {
	prv := NewPrivateKey(Fp503, KeyVariantSidhA)
	pub := NewPublicKey(Fp503, KeyVariantSidhA)
	prv.Generate(rand.Reader)
	for n := 0; n < b.N; n++ {
		prv.GeneratePublicKey(pub)
	}
}

func BenchmarkBobKeyGenPubP751(b *testing.B) {
	prv := NewPrivateKey(Fp751, KeyVariantSidhB)
	pub := NewPublicKey(Fp751, KeyVariantSidhB)
	prv.Generate(rand.Reader)
	for n := 0; n < b.N; n++ {
		prv.GeneratePublicKey(pub)
	}
}

func BenchmarkBobKeyGenPubP503(b *testing.B) {
	prv := NewPrivateKey(Fp503, KeyVariantSidhB)
	pub := NewPublicKey(Fp503, KeyVariantSidhB)
	prv.Generate(rand.Reader)
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

// Examples

func ExamplePrivateKey() {
	// Allice's key pair
	prvA := NewPrivateKey(Fp503, KeyVariantSidhA)
	pubA := NewPublicKey(Fp503, KeyVariantSidhA)
	// Bob's key pair
	prvB := NewPrivateKey(Fp503, KeyVariantSidhB)
	pubB := NewPublicKey(Fp503, KeyVariantSidhB)
	// Generate keypair for Allice
	prvA.Generate(rand.Reader)
	prvA.GeneratePublicKey(pubA)
	// Generate keypair for Bob
	prvB.Generate(rand.Reader)
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
