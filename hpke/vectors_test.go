package hpke

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/sha3"
)

var (
	outputTestVectorEnvironmentKey = "HPKE_TEST_VECTORS_OUT"
	testVectorEncryptionCount      = 257
	testVectorExportLength         = 32
)

func TestVectors(t *testing.T) {
	// Test vectors from
	// https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/master/test-vectors.json
	vectors := readFile(t, "testdata/vectors_rfc9180_5f503c5.json")
	for i, v := range vectors {
		t.Run(fmt.Sprintf("v%v", i), v.verify)
	}
}

func (v *vector) verify(t *testing.T) {
	m := v.ModeID
	kem, kdf, aead := KEM(v.KemID), KDF(v.KdfID), AEAD(v.AeadID)
	if !kem.IsValid() {
		t.Skipf("Skipping test with unknown KEM: %x", kem)
	}
	if !kdf.IsValid() {
		t.Skipf("Skipping test with unknown KDF: %x", kdf)
	}
	if !aead.IsValid() {
		t.Skipf("Skipping test with unknown AEAD: %x", aead)
	}
	s := NewSuite(kem, kdf, aead)

	sender, recv := v.getActors(t, kem.Scheme(), s)
	sealer, opener := v.setup(t, kem.Scheme(), sender, recv, m, s)

	v.checkAead(t, (sealer.(*sealContext)).encdecContext, m)
	v.checkAead(t, (opener.(*openContext)).encdecContext, m)
	v.checkEncryptions(t, sealer, opener, m)
	v.checkExports(t, sealer, m)
	v.checkExports(t, opener, m)
}

func (v *vector) getActors(
	t *testing.T, dhkem kem.Scheme, s Suite,
) (*Sender, *Receiver) {
	h := s.String() + "\n"

	pkR, err := dhkem.UnmarshalBinaryPublicKey(hexB(t, v.PkRm))
	test.CheckNoErr(t, err, h+"bad public key")

	skR, err := dhkem.UnmarshalBinaryPrivateKey(hexB(t, v.SkRm))
	test.CheckNoErr(t, err, h+"bad private key")

	info := hexB(t, v.Info)
	sender, err := s.NewSender(pkR, info)
	test.CheckNoErr(t, err, h+"err sender")

	recv, err := s.NewReceiver(skR, info)
	test.CheckNoErr(t, err, h+"err receiver")

	return sender, recv
}

func (v *vector) setup(t *testing.T, k kem.Scheme,
	se *Sender, re *Receiver,
	m modeID, s Suite,
) (sealer Sealer, opener Opener) {
	seed := hexB(t, v.IkmE)
	rd := bytes.NewReader(seed)

	var enc []byte
	var skS kem.PrivateKey
	var pkS kem.PublicKey
	var errS, errR, errPK, errSK error

	switch v.ModeID {
	case modeBase:
		enc, sealer, errS = se.Setup(rd)
		if errS == nil {
			opener, errR = re.Setup(enc)
		}

	case modePSK:
		psk, pskid := hexB(t, v.Psk), hexB(t, v.PskID)
		enc, sealer, errS = se.SetupPSK(rd, psk, pskid)
		if errS == nil {
			opener, errR = re.SetupPSK(enc, psk, pskid)
		}

	case modeAuth:
		skS, errSK = k.UnmarshalBinaryPrivateKey(hexB(t, v.SkSm))
		if errSK == nil {
			pkS, errPK = k.UnmarshalBinaryPublicKey(hexB(t, v.PkSm))
			if errPK == nil {
				enc, sealer, errS = se.SetupAuth(rd, skS)
				if errS == nil {
					opener, errR = re.SetupAuth(enc, pkS)
				}
			}
		}

	case modeAuthPSK:
		psk, pskid := hexB(t, v.Psk), hexB(t, v.PskID)
		skS, errSK = k.UnmarshalBinaryPrivateKey(hexB(t, v.SkSm))
		if errSK == nil {
			pkS, errPK = k.UnmarshalBinaryPublicKey(hexB(t, v.PkSm))
			if errPK == nil {
				enc, sealer, errS = se.SetupAuthPSK(rd, skS, psk, pskid)
				if errS == nil {
					opener, errR = re.SetupAuthPSK(enc, psk, pskid, pkS)
				}
			}
		}
	}

	h := fmt.Sprintf("mode: %v %v\n", m, s)
	test.CheckNoErr(t, errS, h+"error on sender setup")
	test.CheckNoErr(t, errR, h+"error on receiver setup")
	test.CheckNoErr(t, errSK, h+"bad private key")
	test.CheckNoErr(t, errPK, h+"bad public key")

	return sealer, opener
}

func (v *vector) checkAead(t *testing.T, e *encdecContext, m modeID) {
	got := e.baseNonce
	want := hexB(t, v.BaseNonce)
	if !bytes.Equal(got, want) {
		test.ReportError(t, got, want, m, e.Suite())
	}

	got = e.exporterSecret
	want = hexB(t, v.ExporterSecret)
	if !bytes.Equal(got, want) {
		test.ReportError(t, got, want, m, e.Suite())
	}
}

func (v *vector) checkEncryptions(
	t *testing.T,
	se Sealer,
	op Opener,
	m modeID,
) {
	for j, encv := range v.Encryptions {
		pt := hexB(t, encv.Plaintext)
		aad := hexB(t, encv.Aad)

		ct, err := se.Seal(pt, aad)
		test.CheckNoErr(t, err, "error on sealing")

		got, err := op.Open(ct, aad)
		test.CheckNoErr(t, err, "error on opening")

		want := pt
		if !bytes.Equal(got, want) {
			test.ReportError(t, got, want, m, se.Suite(), j)
		}
	}
}

func (v *vector) checkExports(t *testing.T, context Context, m modeID) {
	for j, expv := range v.Exports {
		ctx := hexB(t, expv.ExportContext)
		want := hexB(t, expv.ExportValue)

		got := context.Export(ctx, uint(expv.ExportLength))
		if !bytes.Equal(got, want) {
			test.ReportError(t, got, want, m, context.Suite(), j)
		}
	}
}

func hexB(t *testing.T, x string) []byte {
	t.Helper()
	z, err := hex.DecodeString(x)
	test.CheckNoErr(t, err, "")
	return z
}

func readFile(t *testing.T, fileName string) []vector {
	jsonFile, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", fileName, err)
	}
	defer jsonFile.Close()
	input, err := io.ReadAll(jsonFile)
	if err != nil {
		t.Fatalf("File %v can not be read. Error: %v", fileName, err)
	}
	var vectors []vector
	err = json.Unmarshal(input, &vectors)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", fileName, err)
	}
	return vectors
}

type encryptionVector struct {
	Aad        string `json:"aad"`
	Ciphertext string `json:"ct"`
	Nonce      string `json:"nonce"`
	Plaintext  string `json:"pt"`
}

type exportVector struct {
	ExportContext string `json:"exporter_context"`
	ExportLength  int    `json:"L"`
	ExportValue   string `json:"exported_value"`
}

type vector struct {
	ModeID             uint8              `json:"mode"`
	KemID              uint16             `json:"kem_id"`
	KdfID              uint16             `json:"kdf_id"`
	AeadID             uint16             `json:"aead_id"`
	Info               string             `json:"info"`
	Ier                string             `json:"ier,omitempty"`
	IkmR               string             `json:"ikmR"`
	IkmE               string             `json:"ikmE,omitempty"`
	SkRm               string             `json:"skRm"`
	SkEm               string             `json:"skEm,omitempty"`
	SkSm               string             `json:"skSm,omitempty"`
	Psk                string             `json:"psk,omitempty"`
	PskID              string             `json:"psk_id,omitempty"`
	PkSm               string             `json:"pkSm,omitempty"`
	PkRm               string             `json:"pkRm"`
	PkEm               string             `json:"pkEm,omitempty"`
	Enc                string             `json:"enc"`
	SharedSecret       string             `json:"shared_secret"`
	KeyScheduleContext string             `json:"key_schedule_context"`
	Secret             string             `json:"secret"`
	Key                string             `json:"key"`
	BaseNonce          string             `json:"base_nonce"`
	ExporterSecret     string             `json:"exporter_secret"`
	Encryptions        []encryptionVector `json:"encryptions"`
	Exports            []exportVector     `json:"exports"`
}

func generateHybridKeyPair(rnd io.Reader, h kem.Scheme) ([]byte, kem.PublicKey, kem.PrivateKey, error) {
	seed := make([]byte, h.SeedSize())
	_, err := rnd.Read(seed)
	if err != nil {
		return nil, nil, nil, err
	}

	pk, sk := h.DeriveKeyPair(seed)
	return seed, pk, sk, nil
}

func mustEncodePublicKey(pk kem.PublicKey) []byte {
	enc, err := pk.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return enc
}

func mustEncodePrivateKey(sk kem.PrivateKey) []byte {
	enc, err := sk.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return enc
}

func generateEncryptions(sealer Sealer, opener Opener, msg []byte) ([]encryptionVector, error) {
	vectors := make([]encryptionVector, testVectorEncryptionCount)
	for i := 0; i < len(vectors); i++ {
		aad := []byte(fmt.Sprintf("Count-%d", i))
		innerSealer := sealer.(*sealContext)
		nonce := innerSealer.calcNonce()
		encrypted, err := sealer.Seal(msg, aad)
		if err != nil {
			return nil, err
		}
		decrypted, err := opener.Open(encrypted, aad)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(decrypted, msg) {
			return nil, fmt.Errorf("Mismatch messages %d", i)
		}
		vectors[i] = encryptionVector{
			Plaintext:  hex.EncodeToString(msg),
			Aad:        hex.EncodeToString(aad),
			Nonce:      hex.EncodeToString(nonce),
			Ciphertext: hex.EncodeToString(encrypted),
		}
	}

	return vectors, nil
}

func generateExports(sealer Sealer, opener Opener) ([]exportVector, error) {
	exportContexts := [][]byte{
		[]byte(""),
		{0x00},
		[]byte("TestContext"),
	}
	vectors := make([]exportVector, len(exportContexts))
	for i := 0; i < len(vectors); i++ {
		senderValue := sealer.Export(exportContexts[i], uint(testVectorExportLength))
		receiverValue := opener.Export(exportContexts[i], uint(testVectorExportLength))
		if !bytes.Equal(senderValue, receiverValue) {
			return nil, fmt.Errorf("Mismatch export values")
		}
		vectors[i] = exportVector{
			ExportContext: hex.EncodeToString(exportContexts[i]),
			ExportLength:  testVectorExportLength,
			ExportValue:   hex.EncodeToString(senderValue),
		}
	}

	return vectors, nil
}

func TestHybridKemRoundTrip(t *testing.T) {
	kemID := KEM_X25519_KYBER768_DRAFT00
	kdfID := KDF_HKDF_SHA256
	aeadID := AEAD_AES128GCM
	rnd := sha3.NewShake128()
	suite := NewSuite(kemID, kdfID, aeadID)
	msg := []byte("To the universal deployment of PQC")
	info := []byte("Hear hear")
	pskid := []byte("before everybody for everybody for everything")
	psk := make([]byte, 32)
	_, _ = rnd.Read(psk)

	ikmR, pkR, skR, err := generateHybridKeyPair(rnd, kemID.Scheme())
	if err != nil {
		t.Error(err)
	}

	ier := make([]byte, 64)
	_, _ = rnd.Read(ier)

	receiver, err := suite.NewReceiver(skR, info)
	if err != nil {
		t.Error(err)
	}

	sender, err := suite.NewSender(pkR, info)
	if err != nil {
		t.Error(err)
	}

	generateVector := func(mode uint8) vector {
		var (
			err2   error
			sealer Sealer
			opener Opener
			enc    []byte
		)
		rnd2 := bytes.NewBuffer(ier)
		switch mode {
		case modeBase:
			enc, sealer, err2 = sender.Setup(rnd2)
			if err2 != nil {
				t.Error(err2)
			}
			opener, err2 = receiver.Setup(enc)
			if err2 != nil {
				t.Error(err2)
			}
		case modePSK:
			enc, sealer, err2 = sender.SetupPSK(rnd2, psk, pskid)
			if err2 != nil {
				t.Error(err2)
			}
			opener, err2 = receiver.SetupPSK(enc, psk, pskid)
			if err2 != nil {
				t.Error(err2)
			}
		default:
			panic("unsupported mode")
		}

		if rnd2.Len() != 0 {
			t.Fatal()
		}

		innerSealer := sealer.(*sealContext)

		encryptions, err2 := generateEncryptions(sealer, opener, msg)
		if err2 != nil {
			t.Error(err2)
		}
		exports, err2 := generateExports(sealer, opener)
		if err2 != nil {
			t.Error(err2)
		}

		ret := vector{
			ModeID:             mode,
			KemID:              uint16(kemID),
			KdfID:              uint16(kdfID),
			AeadID:             uint16(aeadID),
			Ier:                hex.EncodeToString(ier),
			Info:               hex.EncodeToString(info),
			IkmR:               hex.EncodeToString(ikmR),
			SkRm:               hex.EncodeToString(mustEncodePrivateKey(skR)),
			PkRm:               hex.EncodeToString(mustEncodePublicKey(pkR)),
			Enc:                hex.EncodeToString(enc),
			SharedSecret:       hex.EncodeToString(innerSealer.sharedSecret),
			KeyScheduleContext: hex.EncodeToString(innerSealer.keyScheduleContext),
			Secret:             hex.EncodeToString(innerSealer.secret),
			Key:                hex.EncodeToString(innerSealer.key),
			BaseNonce:          hex.EncodeToString(innerSealer.baseNonce),
			ExporterSecret:     hex.EncodeToString(innerSealer.exporterSecret),
			Encryptions:        encryptions,
			Exports:            exports,
		}

		if mode == modePSK {
			ret.Psk = hex.EncodeToString(psk)
			ret.PskID = hex.EncodeToString(pskid)
		}

		return ret
	}

	encodedVector, err := json.Marshal([]vector{
		generateVector(modeBase),
		generateVector(modePSK),
	})
	if err != nil {
		t.Error(err)
	}

	var outputFile string
	if outputFile = os.Getenv(outputTestVectorEnvironmentKey); len(outputFile) > 0 {
		// nolint: gosec
		err = os.WriteFile(outputFile, encodedVector, 0o644)
		if err != nil {
			t.Error(err)
		}
	}
}
