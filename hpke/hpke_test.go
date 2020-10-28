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
	m := hpke.New(v.Mode, v.KemID, v.KdfID, v.AeadID)
	mstr := m.String()

	dhkem, err := m.GetKem()
	test.CheckNoErr(t, err, "bad kem method")

	pkR, err := dhkem.UnmarshalBinaryPublicKey(hexB(v.PkRm))
	test.CheckNoErr(t, err, "bad public key"+mstr)

	enc, sender, err := m.SetupBaseS(pkR, hexB(v.Info))
	test.CheckNoErr(t, err, "error on setup sender"+mstr)

	skR, err := dhkem.UnmarshalBinaryPrivateKey(hexB(v.SkRm))
	test.CheckNoErr(t, err, "bad private key"+mstr)

	recv, err := m.SetupBaseR(skR, enc, hexB(v.Info))
	test.CheckNoErr(t, err, "error on setup receiver"+mstr)

	for j, encv := range v.Encryptions {
		pt := hexB(encv.Plaintext)
		aad := hexB(encv.Aad)

		ct, err := sender.Seal(aad, pt)
		test.CheckNoErr(t, err, "error on sealing"+mstr)

		got, err := recv.Open(aad, ct)
		test.CheckNoErr(t, err, "error on opening"+mstr)

		want := pt
		if !bytes.Equal(got, want) {
			test.ReportError(t, got, want, m, j)
		}
	}
}

func TestVectors(t *testing.T) {
	vectors := readFile(t, "testdata/vectors.json")
	for i, v := range vectors {
		if v.Mode == hpke.Base &&
			v.KemID != hpke.KemX25519Sha256 &&
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
	Mode               uint8  `json:"mode"`
	KemID              uint16 `json:"kem_id"`
	KdfID              uint16 `json:"kdf_id"`
	AeadID             uint16 `json:"aead_id"`
	Info               string `json:"info"`
	IkmR               string `json:"ikmR"`
	IkmE               string `json:"ikmE"`
	SkRm               string `json:"skRm"`
	SkEm               string `json:"skEm"`
	Psk                string `json:"psk"`
	PskID              string `json:"psk_id"`
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
