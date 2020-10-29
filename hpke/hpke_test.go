package hpke_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/internal/test"
)

func (v *vector) verify(t *testing.T) {
	m := v.ModeID
	s := hpke.Suite{v.KemID, v.KdfID, v.AeadID}

	dhkem, err := s.GetKem()
	test.CheckNoErr(t, err, "bad kem method")

	pkR, err := dhkem.UnmarshalBinaryPublicKey(hexB(v.PkRm))
	test.CheckNoErr(t, err, "bad public key")

	skR, err := dhkem.UnmarshalBinaryPrivateKey(hexB(v.SkRm))
	test.CheckNoErr(t, err, "bad private key")

	info := hexB(v.Info)
	sender := s.NewSender(pkR, info)
	recv := s.NewReceiver(skR, info)

	var sealer hpke.Sealer
	var opener hpke.Opener
	var enc []byte
	var errS, errR error

	switch m {
	case hpke.Base:
		enc, sealer, errS = sender.Setup()
		test.CheckNoErr(t, errS, "error on sender setup")
		opener, errR = recv.Setup(enc)
		test.CheckNoErr(t, errR, "error on setup receiver")
	case hpke.PSK:
		psk, pskid := hexB(v.Psk), hexB(v.PskID)

		enc, sealer, errS = sender.SetupPSK(psk, pskid)
		test.CheckNoErr(t, errS, "error on sender setup")
		opener, errR = recv.SetupPSK(enc, psk, pskid)
		test.CheckNoErr(t, errR, "error on setup receiver")
	case hpke.Auth:
		pkS, err := dhkem.UnmarshalBinaryPublicKey(hexB(v.PkSm))
		test.CheckNoErr(t, err, "bad public key")
		skS, err := dhkem.UnmarshalBinaryPrivateKey(hexB(v.SkSm))
		test.CheckNoErr(t, err, "bad private key")

		enc, sealer, errS = sender.SetupAuth(skS)
		test.CheckNoErr(t, errS, "error on sender setup")
		opener, errR = recv.SetupAuth(enc, pkS)
		test.CheckNoErr(t, errR, "error on setup receiver")
	case hpke.AuthPSK:
		psk, pskid := hexB(v.Psk), hexB(v.PskID)
		pkS, err := dhkem.UnmarshalBinaryPublicKey(hexB(v.PkSm))
		test.CheckNoErr(t, err, "bad public key")
		skS, err := dhkem.UnmarshalBinaryPrivateKey(hexB(v.SkSm))
		test.CheckNoErr(t, err, "bad private key")

		enc, sealer, errS = sender.SetupAuthPSK(skS, psk, pskid)
		test.CheckNoErr(t, errS, "error on sender setup")
		opener, errR = recv.SetupAuthPSK(enc, psk, pskid, pkS)
		test.CheckNoErr(t, errR, "error on setup receiver")
	}

	for j, encv := range v.Encryptions {
		pt := hexB(encv.Plaintext)
		aad := hexB(encv.Aad)

		ct, err := sealer.Seal(pt, aad)
		test.CheckNoErr(t, err, "error on sealing")

		got, err := opener.Open(ct, aad)
		test.CheckNoErr(t, err, "error on opening")

		want := pt
		if !bytes.Equal(got, want) {
			test.ReportError(t, got, want, m, s, j)
		}
	}
}

func TestVectors(t *testing.T) {
	vectors := readFile(t, "testdata/vectors.json")
	for i, v := range vectors {
		if v.KemID != hpke.KemX25519Sha256 &&
			v.KemID != hpke.KemX448Sha512 {
			t.Run(fmt.Sprintf("v[%v]", i), v.verify)
		}
	}
}

func hexB(x string) []byte { z, _ := hex.DecodeString(x); return z }

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
