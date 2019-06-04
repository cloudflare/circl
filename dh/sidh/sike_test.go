package sidh

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/cloudflare/circl/dh/sidh/internal/common"
	. "github.com/cloudflare/circl/internal/test"
)

type sikeVec struct {
	id      uint8
	name    string
	kem     *KEM
	KatFile string
	PkB     string
	PrB     string
}

var tdataSike = map[uint8]sikeVec{
	FP_503: {
		FP_503, "P-503", NewSike503(rand.Reader),
		"testdata/PQCkemKAT_434.rsp",
		"68460C22466E95864CFEA7B5D9077E768FF4F9ED69AE56D7CF3F236FB06B31020EEE34B5B572CEA5DDF20B531966AA8F5F3ACC0C6D1CE04EEDC30FD1F1233E2D96FE60C6D638FC646EAF2E2246F1AEC96859CE874A1F029A78F9C978CD6B22114A0D5AB20101191FD923E80C76908B1498B9D0200065CCA09159A0C65A1E346CC6470314FE78388DAA89DD08EC67DBE63C1F606674ACC49EBF9FDBB2B898B3CE733113AA6F942DB401A76D629CE6EE6C0FDAF4CFB1A5E366DB66C17B3923A1B7FB26A3FF25B9018869C674D3DEF4AF269901D686FE4647F9D2CDB2CEB3AFA305B27C885F037ED167F595066C21E7DD467D8332B934A5102DA5F13332DFA356B82156A0BB2E7E91C6B85B7D1E381BC9E3F0FC4DB9C36016D9ECEC415D7E977E9AC29910D934BA2FE4EE49D3B387607A4E1AFABF495FB86A77194626589E802FF5167C7A25C542C1EAD25A6E0AA931D94F2F9AFD3DBDF222E651F729A90E77B20974905F1E65E041CE6C95AAB3E1F22D332E0A5DE9C5DB3D9C7A38",
		"80FC55DA74DEFE3113487B80841E678AF9ED4E0599CF07353A4AB93971C090A0A9402C9DC98AC6DC8F5FDE5E970AE22BA48A400EFC72851C"},
	FP_751: {
		FP_751, "P-751", NewSike751(rand.Reader),
		"testdata/PQCkemKAT_644.rsp",
		"7C55E268665504B9A11A1B30B4363A4957960AD015A7B74DF39FB0141A95CC51A4BEBBB48452EF0C881220D68CB5FF904C0549F05F06BF49A520E684DD610A7E121B420C751B789BDCDB8B6EC136BA0CE74EB6904906057EA7343839EA35FAF2C3D7BE76C81DCA4DF0850CE5F111FF9FF97242EC5520310D7F90A004BACFD75408CBFE8948232A9CCF035136DE3691D9BEF110C3081AADF0D2328CE2CC94998D8AE94D6575083FAFA045F50201FCE841D01C214CC8BBEFCC701484215EA70518204C76A0DA89BEAF0B066F6FD9E78A2C908CF0AFF74E0B55477190F918397F0CF3A537B7911DA846196AD914114A15C2F3C1062D78B19D23348C3D3D4A9C2B2018B382CC44544DA2FA263EB6212D2D13F254216DE002D4AEA55C75C5349A681D7A809BCC29C4CAE1168AC790321FF7429FAAC2FC09465F93E10B9DD970901A1B1D045DDAC9D7B901E00F29AA9F2C87C8EF848E80B7B290ECF85D6BB4C7E975A939A7AFB63069F900A75C9B7B71C2E7472C21A87AB604B6372D4EBEC5974A711281A819636D8FA3E6608F2B81F35599BBB4A1EB5CBD8F743587550F8CE3A809F5C9C399DD52B2D15F217A36F3218C772FD4E67F67D526DEBE1D31FEC4634927A873A1A6CFE55FF1E35AB72EBBD22E3CDD9D2640813345015BB6BD25A6977D0391D4D78998DD178155FEBF247BED3A9F83EAF3346BA90098B908B2359B60491C94330626709D235D1CFB7C87DCA779CFBA23DA280DC06FAEA0FDB3773B0C6391F889D803B7C04AC6AB27375B440336789823176C57",
		"00010203040506070809000102030405060708090001020304050607080901028626ED79D451140800E03B59B956F8210E556067407D13DC90FA9E8B872BFB8FAB0A7289852106E40538D3575C500201"},
}

// Encrypt, Decrypt, check if input/output plaintext is the same
func testPKERoundTrip(t *testing.T, v sikeVec) {
	// Message to be encrypted
	var pt [common.MAX_MSG_BSZ]byte
	var params = common.Params(v.id)
	var ct = make([]byte, v.kem.CiphertextSize())
	var msg = make([]byte, params.MsgLen)
	for i, _ := range msg {
		msg[i] = byte(i)
	}

	// Import keys
	pkB := NewPublicKey(params.Id, KeyVariant_SIKE)
	skB := NewPrivateKey(params.Id, KeyVariant_SIKE)
	pk_hex, err := hex.DecodeString(v.PkB)
	CheckNoErr(t, err, "Test vector wrong")
	sk_hex, err := hex.DecodeString(v.PrB)
	CheckNoErr(t, err, "Test vector wrong")
	err = pkB.Import(pk_hex)
	CheckNoErr(t, err, "Public key import failed")
	err = skB.Import(sk_hex)
	CheckNoErr(t, err, "Private key import failed")
	err = v.kem.encrypt(ct, rand.Reader, pkB, msg[:])
	CheckNoErr(t, err, "PKE roundtrip - encryption failed")
	pt_len := v.kem.decrypt(pt[:], skB, ct)
	CheckNoErr(t, err, "PKE roundtrip - decription failed")

	if !bytes.Equal(pt[:pt_len], msg[:]) {
		t.Errorf("Decryption failed \n got : %X\n exp : %X", pt[:pt_len], msg)
	}
}

// Generate key and check if can encrypt
func testPKEKeyGeneration(t *testing.T, v sikeVec) {
	var err error
	var params = common.Params(v.id)
	var pt [common.MAX_MSG_BSZ]byte
	var msg = make([]byte, params.MsgLen)
	var ct = make([]byte, v.kem.CiphertextSize())
	// static buffer to ensure no overrides
	var pk = NewPublicKey(v.id, KeyVariant_SIKE)
	var sk = NewPrivateKey(v.id, KeyVariant_SIKE)

	for i, _ := range msg {
		msg[i] = byte(i)
	}

	err = sk.Generate(rand.Reader)
	CheckNoErr(t, err, "PKE key generation")
	sk.GeneratePublicKey(pk)

	err = v.kem.encrypt(ct, rand.Reader, pk, msg[:])
	CheckNoErr(t, err, "PKE encryption")
	pt_len := v.kem.decrypt(pt[:], sk, ct)
	CheckNoErr(t, err, "PKE key decryption")

	if !bytes.Equal(pt[:pt_len], msg[:]) {
		t.Fatalf("Decryption failed \n got : %X\n exp : %X", pt, msg)
	}
}

func testNegativePKE(t *testing.T, v sikeVec) {
	var err error
	var msg [common.MAX_MSG_BSZ]byte
	var ct = make([]byte, v.kem.CiphertextSize())
	var pk = NewPublicKey(v.id, KeyVariant_SIKE)
	var sk = NewPrivateKey(v.id, KeyVariant_SIKE)

	// Generate key
	err = sk.Generate(rand.Reader)
	CheckNoErr(t, err, "key generation")
	sk.GeneratePublicKey(pk)

	// bytelen(msg) - 1
	err = v.kem.encrypt(ct, rand.Reader, pk, msg[:v.kem.params.KemSize+8-1])
	CheckIsErr(t, err, "PKE encryption doesn't fail")
	for _, v := range ct {
		if v != 0 {
			t.Fatal("Returned ciphertext must be not changed")
		}
	}
}

func testKEMRoundTrip(t *testing.T, pkB, skB []byte, v sikeVec) {
	// Import keys
	var err error
	var ss_e [common.MAX_SHARED_SECRET_BSZ]byte
	var ss_d [common.MAX_SHARED_SECRET_BSZ]byte
	var pk = NewPublicKey(v.id, KeyVariant_SIKE)
	var sk = NewPrivateKey(v.id, KeyVariant_SIKE)
	var ct = make([]byte, v.kem.CiphertextSize())
	var ssBsz = v.kem.SharedSecretSize()

	err = pk.Import(pkB)
	CheckNoErr(t, err, "Public key import failed")
	err = sk.Import(skB)
	CheckNoErr(t, err, "Private key import failed")

	v.kem.Reset()
	err = v.kem.Encapsulate(ct, ss_e[:], pk)
	CheckNoErr(t, err, "Encapsulation failed")
	v.kem.Reset()
	err = v.kem.Decapsulate(ss_d[:ssBsz], sk, pk, ct)
	CheckNoErr(t, err, "Decapsulation failed")

	if !bytes.Equal(ss_e[:v.kem.SharedSecretSize()], ss_d[:v.kem.SharedSecretSize()]) {
		t.Error("Shared secrets from decapsulation and encapsulation differ")
	}
}

func testKEMKeyGeneration(t *testing.T, v sikeVec) {
	var ss_e [common.MAX_SHARED_SECRET_BSZ]byte
	var ss_d [common.MAX_SHARED_SECRET_BSZ]byte
	var ct = make([]byte, v.kem.CiphertextSize())

	sk := NewPrivateKey(v.id, KeyVariant_SIKE)
	pk := NewPublicKey(v.id, KeyVariant_SIKE)
	CheckNoErr(t, sk.Generate(rand.Reader), "error: key generation")
	sk.GeneratePublicKey(pk)

	// calculated shared secret
	v.kem.Reset()
	err := v.kem.Encapsulate(ct, ss_e[:], pk)
	CheckNoErr(t, err, "encapsulation failed")
	v.kem.Reset()
	err = v.kem.Decapsulate(ss_d[:v.kem.SharedSecretSize()], sk, pk, ct)
	CheckNoErr(t, err, "decapsulation failed")

	if !bytes.Equal(ss_e[:], ss_d[:]) {
		t.Fatalf("KEM failed \n encapsulated: %X\n decapsulated: %X", ss_d[:], ss_e[:])
	}
}

func testNegativeKEM(t *testing.T, v sikeVec) {
	var ss_e [common.MAX_SHARED_SECRET_BSZ]byte
	var ss_d [common.MAX_SHARED_SECRET_BSZ]byte
	var ss_tmp [common.MAX_SHARED_SECRET_BSZ]byte
	var ct = make([]byte, v.kem.CiphertextSize())
	var ssBsz = v.kem.SharedSecretSize()

	sk := NewPrivateKey(v.id, KeyVariant_SIKE)
	pk := NewPublicKey(v.id, KeyVariant_SIKE)
	CheckNoErr(t, sk.Generate(rand.Reader), "error: key generation")
	sk.GeneratePublicKey(pk)

	v.kem.Reset()
	err := v.kem.Encapsulate(ct, ss_e[:], pk)
	CheckNoErr(t, err, "pre-requisite for a test failed")

	// Try decapsulate too small ciphertext
	v.kem.Reset()
	CheckNoErr(
		t,
		CheckPanic(func() { v.kem.Decapsulate(ss_tmp[:ssBsz], sk, pk, ct[:len(ct)-2]) }),
		"Decapsulation must panic if ciphertext is too small")

	ctTmp := make([]byte, len(ct)+1)
	// Try decapsulate too big ciphertext
	v.kem.Reset()
	CheckNoErr(
		t,
		CheckPanic(func() { v.kem.Decapsulate(ss_tmp[:ssBsz], sk, pk, ctTmp) }),
		"Decapsulation must panic if ciphertext is too big")

	// Change ciphertext
	ct[0] = ct[0] - 1
	v.kem.Reset()
	err = v.kem.Decapsulate(ss_d[:ssBsz], sk, pk, ct)
	CheckNoErr(t, err, "decapsulation returns error when invalid ciphertext provided")

	if bytes.Equal(ss_e[:], ss_d[:]) {
		// no idea how this could ever happen, but it would be very bad
		t.Error("critical error")
	}

	// Try encapsulating with SIDH key
	pkSidh := NewPublicKey(v.id, KeyVariant_SIDH_B)
	prSidh := NewPrivateKey(v.id, KeyVariant_SIDH_B)
	v.kem.Reset()
	CheckNoErr(
		t,
		CheckPanic(func() { v.kem.Encapsulate(ct, ss_e[:], pkSidh) }),
		"encapsulation accepts SIDH public key")

	// Try decapsulating with SIDH key
	v.kem.Reset()
	CheckNoErr(
		t,
		CheckPanic(func() { v.kem.Decapsulate(ss_d[:ssBsz], prSidh, pk, ct) }),
		"encapsulation accepts SIDH public key")
}

// In case invalid ciphertext is provided, SIKE's decapsulation must
// return same (but unpredictable) result for a given key.
func testNegativeKEMSameWrongResult(t *testing.T, v sikeVec) {
	var ss_e [common.MAX_SHARED_SECRET_BSZ]byte
	var ss_d1 [common.MAX_SHARED_SECRET_BSZ]byte
	var ss_d2 [common.MAX_SHARED_SECRET_BSZ]byte
	var ct = make([]byte, v.kem.CiphertextSize())
	var ssBsz = v.kem.SharedSecretSize()

	sk := NewPrivateKey(v.id, KeyVariant_SIKE)
	pk := NewPublicKey(v.id, KeyVariant_SIKE)
	CheckNoErr(t, sk.Generate(rand.Reader), "error: key generation")
	sk.GeneratePublicKey(pk)

	v.kem.Reset()
	err := v.kem.Encapsulate(ct, ss_e[:], pk)
	CheckNoErr(t, err, "pre-requisite for a test failed")

	// make ciphertext wrong
	ct[0] = ct[0] - 1
	v.kem.Reset()
	err = v.kem.Decapsulate(ss_d1[:ssBsz], sk, pk, ct)
	CheckNoErr(t, err, "pre-requisite for a test failed")

	// change secret keysecond decapsulation must be done with same, but imported private key
	var expSk [common.MAX_SIKE_PRIVATE_KEY_BSZ]byte
	sk.Export(expSk[:])

	// create new private key
	sk = NewPrivateKey(v.id, KeyVariant_SIKE)
	CheckNoErr(t, sk.Import(expSk[:sk.Size()]), "import failed")

	// try decapsulating again.
	v.kem.Reset()
	err = v.kem.Decapsulate(ss_d2[:ssBsz], sk, pk, ct)
	CheckNoErr(t, err, "pre-requisite for a test failed")

	// ss_d1 must be same as ss_d2
	if !bytes.Equal(ss_d1[:], ss_d2[:]) {
		t.Error("decapsulation is insecure")
	}

	// ss_d1 and ss_d2 must be different than ss_e
	if bytes.Equal(ss_e[:], ss_d1[:]) || bytes.Equal(ss_e[:], ss_d2[:]) {
		// this test requires that decapsulation returns wrong result
		t.Errorf("test implementation error")
	}
}

func testKAT(t *testing.T, v sikeVec) {
	ssGot := make([]byte, v.kem.SharedSecretSize())
	testDecapsulation := func(pk, sk, ct, ssExpected []byte) {
		var pubKey = NewPublicKey(v.id, KeyVariant_SIKE)
		var prvKey = NewPrivateKey(v.id, KeyVariant_SIKE)
		if pubKey.Import(pk) != nil || prvKey.Import(sk) != nil {
			panic("sike test: can't load KAT")
		}

		err := v.kem.Decapsulate(ssGot, prvKey, pubKey, ct)
		CheckNoErr(t, err, "sike test: can't perform degcapsulation KAT")
		if !bytes.Equal(ssGot, ssExpected) {
			t.Fatalf("KAT decapsulation failed\n")
		}
	}

	readAndCheckLine := func(r *bufio.Reader) []byte {
		// Read next line from buffer
		line, isPrefix, err := r.ReadLine()
		if err != nil || isPrefix {
			panic("Wrong format of input file")
		}

		// Function expects that line is in format "KEY = HEX_VALUE". Get
		// value, which should be a hex string
		hexst := strings.Split(string(line), "=")[1]
		hexst = strings.TrimSpace(hexst)
		// Convert value to byte string
		ret, err := hex.DecodeString(hexst)
		if err != nil {
			panic("Wrong format of input file")
		}
		return ret
	}

	testKeygen := func(pk, sk []byte) bool {
		// Import provided private key
		var prvKey = NewPrivateKey(v.id, KeyVariant_SIKE)
		var pubKey = NewPublicKey(v.id, KeyVariant_SIKE)
		var pubKeyBytes = make([]byte, pubKey.Size())
		CheckNoErr(t, prvKey.Import(sk), "Can't load KAT")

		// Generate public key
		prvKey.GeneratePublicKey(pubKey)
		pubKey.Export(pubKeyBytes)
		return bytes.Equal(pubKeyBytes, pk)
	}

	f, err := os.Open(v.KatFile)
	if err != nil {
		t.Fatal(err)
	}

	r := bufio.NewReader(f)
	for {
		line, isPrefix, err := r.ReadLine()
		if err != nil || isPrefix {
			if err == io.EOF {
				break
			} else {
				t.Fatal(err)
			}
		}
		if len(strings.TrimSpace(string(line))) == 0 || line[0] == '#' {
			continue
		}

		// count
		_ = strings.Split(string(line), "=")[1]
		// seed
		_ = readAndCheckLine(r)
		// pk
		pk := readAndCheckLine(r)
		// sk (secret key in test vector is concatenation of
		// MSG + SECRET_BOB_KEY + PUBLIC_BOB_KEY. We use only MSG+SECRET_BOB_KEY
		sk := readAndCheckLine(r)
		sk = sk[:v.kem.params.MsgLen+int(v.kem.params.B.SecretByteLen)]
		// ct
		ct := readAndCheckLine(r)
		// ss
		ss := readAndCheckLine(r)

		testKeygen(pk, sk)
		testDecapsulation(pk, sk, ct, ss)
		testKEMRoundTrip(t, pk, sk, v)
	}
}

// Interface to "testing"

/* -------------------------------------------------------------------------
   Wrappers for 'testing' SIDH
   -------------------------------------------------------------------------*/
func testSike(t *testing.T, m *map[uint8]sikeVec, f func(t *testing.T, v sikeVec)) {
	for _, v := range *m {
		t.Run(v.name, func(t *testing.T) { f(t, v) })
	}
}

func TestPKERoundTrip(t *testing.T)     { testSike(t, &tdataSike, testPKERoundTrip) }
func TestPKEKeyGeneration(t *testing.T) { testSike(t, &tdataSike, testPKEKeyGeneration) }
func TestNegativePKE(t *testing.T)      { testSike(t, &tdataSike, testNegativePKE) }
func TestKEMKeyGeneration(t *testing.T) { testSike(t, &tdataSike, testKEMKeyGeneration) }
func TestNegativeKEM(t *testing.T)      { testSike(t, &tdataSike, testNegativeKEM) }
func TestKAT(t *testing.T)              { testSike(t, &tdataSike, testKAT) }
func TestNegativeKEMSameWrongResult(t *testing.T) {
	testSike(t, &tdataSike, testNegativeKEMSameWrongResult)
}

func TestKEMRoundTrip(t *testing.T) {
	for _, val := range tdataSike {
		//		fmt.Printf("\tTesting: %s\n", val.name)
		pk, err := hex.DecodeString(val.PkB)
		CheckNoErr(t, err, "public key B not a number")
		sk, err := hex.DecodeString(val.PrB)
		CheckNoErr(t, err, "private key B not a number")
		testKEMRoundTrip(t, pk, sk, val)
	}
}

/* -------------------------------------------------------------------------
   Benchmarking
   -------------------------------------------------------------------------*/

func benchSike(t *testing.B, m *map[uint8]sikeVec, f func(t *testing.B, v sikeVec)) {
	for _, v := range *m {
		t.Run(v.name, func(t *testing.B) { f(t, v) })
	}
}

func benchKeygen(b *testing.B, v sikeVec) {
	pub := NewPublicKey(v.id, KeyVariant_SIKE)
	prv := NewPrivateKey(v.id, KeyVariant_SIKE)
	prv.Generate(rand.Reader)

	for n := 0; n < b.N; n++ {
		prv.GeneratePublicKey(pub)
	}
}

func benchmarkEncaps(b *testing.B, v sikeVec) {
	pub := NewPublicKey(v.id, KeyVariant_SIKE)
	prv := NewPrivateKey(v.id, KeyVariant_SIKE)

	if prv.Generate(rand.Reader) != nil {
		b.FailNow()
	}
	prv.GeneratePublicKey(pub)

	var ct [common.MAX_CIPHERTEXT_BSZ]byte
	var ss [common.MAX_SHARED_SECRET_BSZ]byte

	for n := 0; n < b.N; n++ {
		v.kem.Reset()
		v.kem.Encapsulate(ct[:], ss[:], pub)
	}
}

func benchmarkDecaps(b *testing.B, v sikeVec) {
	var ct [common.MAX_CIPHERTEXT_BSZ]byte
	var ss [common.MAX_SHARED_SECRET_BSZ]byte
	var ssBsz = v.kem.SharedSecretSize()

	pkA := NewPublicKey(v.id, KeyVariant_SIKE)
	prvA := NewPrivateKey(v.id, KeyVariant_SIKE)
	pkB := NewPublicKey(v.id, KeyVariant_SIKE)
	prvB := NewPrivateKey(v.id, KeyVariant_SIKE)

	if prvA.Generate(rand.Reader) != nil || prvB.Generate(rand.Reader) != nil {
		b.FailNow()
	}

	prvA.GeneratePublicKey(pkA)
	prvB.GeneratePublicKey(pkB)

	v.kem.Reset()
	err := v.kem.Encapsulate(ct[:], ss[:], pkA)
	if err != nil {
		b.FailNow()
	}

	ctSlc := ct[:v.kem.CiphertextSize()]
	for n := 0; n < b.N; n++ {
		v.kem.Reset()
		v.kem.Decapsulate(ss[:ssBsz], prvA, pkB, ctSlc)
	}
}

func BenchmarkKeygen(b *testing.B) { benchSike(b, &tdataSike, benchKeygen) }
func BenchmarkEncaps(b *testing.B) { benchSike(b, &tdataSike, benchmarkEncaps) }
func BenchmarkDecaps(b *testing.B) { benchSike(b, &tdataSike, benchmarkDecaps) }

// Examples
func ExampleKEM() {
	// Allice's key pair
	prvA := NewPrivateKey(FP_503, KeyVariant_SIKE)
	pubA := NewPublicKey(FP_503, KeyVariant_SIKE)
	// Bob's key pair
	prvB := NewPrivateKey(FP_503, KeyVariant_SIKE)
	pubB := NewPublicKey(FP_503, KeyVariant_SIKE)
	// Generate keypair for Allice
	prvA.Generate(rand.Reader)
	prvA.GeneratePublicKey(pubA)
	// Generate keypair for Bob
	prvB.Generate(rand.Reader)
	prvB.GeneratePublicKey(pubB)
	// Initialize internal KEM structures
	var kem = NewSike503(rand.Reader)
	// Create buffers for ciphertext, shared secret received
	// from encapsulation and shared secret from decapsulation
	ct := make([]byte, kem.CiphertextSize())
	ssE := make([]byte, kem.SharedSecretSize())
	ssD := make([]byte, kem.SharedSecretSize())
	// Allice performs encapsulation with Bob's public key
	kem.Encapsulate(ct, ssE, pubB)
	// Bob performs decapsulation with his key pair
	kem.Decapsulate(ssD, prvB, pubB, ct)
	fmt.Printf("%t\n", bytes.Equal(ssE, ssD))

	// Bob performs encapsulation with Allices's public key
	kem.Encapsulate(ct, ssE, pubA)
	// Allice performs decapsulation with hers key pair
	kem.Decapsulate(ssD, prvA, pubA, ct)
	fmt.Printf("%t\n", bytes.Equal(ssE, ssD))

	// Output:
	// true
	// true
}
