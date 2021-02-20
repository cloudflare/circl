package oprf

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
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
		Info   string `json:"Info"`
		Input  string `json:"Input"`
		Output string `json:"Output"`
	} `json:"vectors"`
}

func toBytes(t *testing.T, s, errMsg string) []byte {
	bytes, err := hex.DecodeString(s)
	test.CheckNoErr(t, err, "decoding "+errMsg)
	return bytes
}

func toListBytes(t *testing.T, s, errMsg string) [][]byte {
	strs := strings.Split(s, ",")
	out := make([][]byte, len(strs))
	for i := range strs {
		out[i] = toBytes(t, strs[i], errMsg)
	}
	return out
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

func (v *vector) SetUpParties(t *testing.T) (s *Server, c *Client) {
	skSm := toBytes(t, v.SkSm, "private key")
	privateKey := new(PrivateKey)
	err := privateKey.Deserialize(v.ID, skSm)
	test.CheckNoErr(t, err, "invalid private key")

	if v.Mode == BaseMode {
		s, err = NewServer(v.ID, privateKey)
	} else if v.Mode == VerifiableMode {
		s, err = NewVerifiableServer(v.ID, privateKey)
	}
	test.CheckNoErr(t, err, "invalid setup of server")

	if v.Mode == BaseMode {
		c, err = NewClient(v.ID)
	} else if v.Mode == VerifiableMode {
		pkSm := toBytes(t, v.PkSm, "public key")
		publicKey := new(PublicKey)
		err = publicKey.Deserialize(v.ID, pkSm)
		test.CheckNoErr(t, err, "invalid public key")
		c, err = NewVerifiableClient(v.ID, publicKey)
	}
	test.CheckNoErr(t, err, "invalid setup of client")

	return s, c
}

func (v *vector) compareLists(t *testing.T, got, want [][]byte) {
	for i := range got {
		if !bytes.Equal(got[i], want[i]) {
			test.ReportError(t, got[i], want[i], v.Name, v.Mode, i)
		}
	}
}

func (v *vector) test(t *testing.T) {
	server, client := v.SetUpParties(t)

	var publicKey *PublicKey
	if v.Mode == VerifiableMode {
		pkSm := toBytes(t, v.PkSm, "public key")
		publicKey = new(PublicKey)
		err := publicKey.Deserialize(v.ID, pkSm)
		test.CheckNoErr(t, err, "invalid public key")
	}

	for i, vi := range v.Vectors {
		inputs := toListBytes(t, vi.Input, "input")
		blindsBytes := toListBytes(t, vi.Blind, "blind")

		blinds := make([]Blind, len(blindsBytes))
		for j := range blindsBytes {
			blinds[j] = client.suite.Group.NewScalar()
			err := blinds[j].UnmarshalBinary(blindsBytes[j])
			test.CheckNoErr(t, err, "invalid blind")
		}

		clientReq, err := client.blind(inputs, blinds)
		test.CheckNoErr(t, err, "invalid client request")
		v.compareLists(t,
			clientReq.BlindedElements,
			toListBytes(t, vi.BlindedElement, "blindedElement"),
		)

		eval, err := server.Evaluate(clientReq.BlindedElements)
		test.CheckNoErr(t, err, "invalid evaluation")
		v.compareLists(t,
			eval.Elements,
			toListBytes(t, vi.EvaluationElement, "evaluation"),
		)

		outputs, err := client.Finalize(clientReq, eval)
		test.CheckNoErr(t, err, "invalid finalize")
		expectedOutputs := toListBytes(t, vi.Output, "output")
		v.compareLists(t,
			outputs,
			expectedOutputs,
		)

		for j := range inputs {
			output, err := server.FullEvaluate(inputs[j])
			test.CheckNoErr(t, err, "invalid full evaluate")
			got := output
			want := expectedOutputs[j]
			if !bytes.Equal(got, want) {
				test.ReportError(t, got, want, v.Name, v.Mode, i, j)
			}

			test.CheckOk(server.VerifyFinalize(inputs[j], output), "verify finalize", t)
		}
	}
}

func TestVectors(t *testing.T) {
	// Test vectors from https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf
	v := readFile(t, "testdata/allVectors_v06.json")

	for i := range v {
		id := v[i].ID
		if !(id == OPRFP256 || id == OPRFP384 || id == OPRFP521) {
			t.Logf(v[i].Name + " not supported yet")
			continue
		}
		t.Run(fmt.Sprintf("Suite%v/Mode%v", id, v[i].Mode), v[i].test)
	}
}
