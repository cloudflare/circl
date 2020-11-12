package oprf

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

type vector struct {
	ID      uint16 `json:"suiteID"`
	Name    string `json:"suiteName"`
	Mode    uint8  `json:"mode"`
	Hash    string `json:"hash"`
	PkSm    string `json:"pkSm"`
	SkSm    string `json:"skSm"`
	Vectors []struct {
		Batch             int    `json:"Batch"`
		Blind             string `json:"Blind"`
		BlindedElement    string `json:"BlindedElement"`
		EvaluationElement string `json:"EvaluationElement"`
		EvaluationProof   struct {
			C string `json:"c"`
			S string `json:"s"`
		} `json:"EvaluationProof"`
		Info             string `json:"Info"`
		Input            string `json:"Input"`
		Output           string `json:"Output"`
		UnblindedElement string `json:"UnblindedElement"`
	} `json:"vectors"`
}

func toBytes(t *testing.T, s, errMsg string) []byte {
	bytes, err := hex.DecodeString(s[2:])
	test.CheckNoErr(t, err, "decoding "+errMsg)
	return bytes
}

func readFile(t *testing.T, fileName string) []vector {
	jsonFile, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", fileName, err)
	}
	defer jsonFile.Close()
	input, _ := ioutil.ReadAll(jsonFile)

	var v []vector
	err = json.Unmarshal(input, &v)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", fileName, err)
	}
	return v
}

func (v *vector) SetUpParties(t *testing.T) (*Server, *Client) {
	privateKey := toBytes(t, v.SkSm, "private key")

	keyPair := new(KeyPair)
	err := keyPair.Deserialize(v.ID, privateKey)
	test.CheckNoErr(t, err, "invalid private key")

	srv, err := NewServerWithKeyPair(v.ID, *keyPair)
	test.CheckNoErr(t, err, "invalid setup of server")

	client, err := NewClient(v.ID)
	test.CheckNoErr(t, err, "invalid setup of client")

	return srv, client
}

func (v *vector) test(t *testing.T) {
	server, client := v.SetUpParties(t)
	blind := client.GetGroup().NewScl()

	for i, vi := range v.Vectors {
		input := toBytes(t, vi.Input, "input")
		err := blind.UnmarshalBinary(toBytes(t, vi.Blind, "blind"))
		test.CheckNoErr(t, err, "invalid blind")

		clientReq, err := client.blind(input, blind)
		test.CheckNoErr(t, err, "invalid client request")
		got := clientReq.BlindedToken
		want := toBytes(t, vi.BlindedElement, "blindedElement")
		if !bytes.Equal(got, want) {
			test.ReportError(t, got, want, v.Name, v.Mode, i)
		}

		eval, err := server.Evaluate(clientReq.BlindedToken)
		test.CheckNoErr(t, err, "invalid evaluation")
		got = eval.Element
		want = toBytes(t, vi.EvaluationElement, "evaluation")
		if !bytes.Equal(got, want) {
			test.ReportError(t, got, want, v.Name, v.Mode, i)
		}

		unblindedToken, err := clientReq.unblind(eval)
		test.CheckNoErr(t, err, "invalid unblindedToken")
		got = unblindedToken
		want = toBytes(t, vi.UnblindedElement, "unblindedelement")
		if !bytes.Equal(got, want) {
			test.ReportError(t, got, want, v.Name, v.Mode, i)
		}

		info := toBytes(t, vi.Info, "info")
		output, err := clientReq.Finalize(eval, info)
		test.CheckNoErr(t, err, "invalid finalize")
		got = output
		want = toBytes(t, vi.Output, "output")
		if !bytes.Equal(got, want) {
			test.ReportError(t, got, want, v.Name, v.Mode, i)
		}
	}
}

func TestVectors(t *testing.T) {
	// Test vectors from https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf
	v := readFile(t, "testdata/allVectors_v06.json")

	for i := range v {
		id := v[i].ID
		mode := v[i].Mode

		if !(id == OPRFP256 || id == OPRFP384 || id == OPRFP521) {
			t.Logf(v[i].Name + " not supported yet")
			continue
		}
		if !(mode == BaseMode) {
			t.Logf("VerifiableMode not supported yet")
			continue
		}
		t.Run(fmt.Sprintf("Suite#%v/Mode#%v", id, mode), v[i].test)
	}
}
