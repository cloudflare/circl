package hpke

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/kem"
)

func TestVectors(t *testing.T) {
	// Test vectors from
	// https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/master/test-vectors.json
	vectors := readFile(t, "testdata/vectors_v08_779d028.json")
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
	input, _ := ioutil.ReadAll(jsonFile)
	var vectors []vector
	err = json.Unmarshal(input, &vectors)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", fileName, err)
	}
	return vectors
}

type vector struct {
	ModeID             uint8  `json:"mode"`
	KemID              uint16 `json:"kem_id"`
	KdfID              uint16 `json:"kdf_id"`
	AeadID             uint16 `json:"aead_id"`
	Info               string `json:"info"`
	IkmR               string `json:"ikmR"`
	IkmE               string `json:"ikmE"`
	SkRm               string `json:"skRm"`
	SkEm               string `json:"skEm"`
	SkSm               string `json:"skSm"`
	Psk                string `json:"psk"`
	PskID              string `json:"psk_id"`
	PkSm               string `json:"pkSm"`
	PkRm               string `json:"pkRm"`
	PkEm               string `json:"pkEm"`
	Enc                string `json:"enc"`
	SharedSecret       string `json:"shared_secret"`
	KeyScheduleContext string `json:"key_schedule_context"`
	Secret             string `json:"secret"`
	Key                string `json:"key"`
	BaseNonce          string `json:"base_nonce"`
	ExporterSecret     string `json:"exporter_secret"`
	Encryptions        []struct {
		Aad        string `json:"aad"`
		Ciphertext string `json:"ciphertext"`
		Nonce      string `json:"nonce"`
		Plaintext  string `json:"plaintext"`
	} `json:"encryptions"`
	Exports []struct {
		ExportContext string `json:"exportContext"`
		ExportLength  int    `json:"exportLength"`
		ExportValue   string `json:"exportValue"`
	} `json:"exports"`
}
