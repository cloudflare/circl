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

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/internal/test"
)

type vector struct {
	ID       uint16 `json:"suiteID"`
	Name     string `json:"suiteName"`
	Mode     uint8  `json:"mode"`
	Hash     string `json:"hash"`
	PkSm     string `json:"pkSm"`
	SkSm     string `json:"skSm"`
	Seed     string `json:"seed"`
	GroupDST string `json:"groupDST"`
	Vectors  []struct {
		Batch             int    `json:"Batch"`
		Blind             string `json:"Blind"`
		Info              string `json:"Info"`
		BlindedElement    string `json:"BlindedElement"`
		EvaluationElement string `json:"EvaluationElement"`
		Proof             struct {
			Proof string `json:"proof"`
			R     string `json:"r"`
		} `json:"Proof"`
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

func toScalar(t *testing.T, g group.Group, s, errMsg string) group.Scalar {
	r := g.NewScalar()
	rBytes := toBytes(t, s, errMsg)
	err := r.UnmarshalBinary(rBytes)
	test.CheckNoErr(t, err, errMsg)
	return r
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
	seed := toBytes(t, v.Seed, "seed for keys")
	privateKey, err := DeriveKey(v.ID, v.Mode, seed)
	test.CheckNoErr(t, err, "deriving key")

	got, err := privateKey.Serialize()
	test.CheckNoErr(t, err, "serlalizing key")
	want := toBytes(t, v.SkSm, "private key")
	if !bytes.Equal(got, want) {
		test.ReportError(t, got, want, v.Name, v.Mode)
	}

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
	t.Helper()
	for i := range got {
		if !bytes.Equal(got[i], want[i]) {
			test.ReportError(t, got[i], want[i], v.Name, v.Mode, i)
		}
	}
}

func (v *vector) compareStrings(t *testing.T, got, want string) {
	t.Helper()
	if got != want {
		test.ReportError(t, got, want, v.Name, v.Mode)
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
		info := toBytes(t, vi.Info, "info")
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
			clientReq.BlindedElements(),
			toListBytes(t, vi.BlindedElement, "blindedElement"),
		)

		rr := toScalar(t, client.suite.Group, vi.Proof.R, "invalid proof random scalar")

		eval, err := server.evaluateWithProofScalar(clientReq.BlindedElements(), info, rr)
		test.CheckNoErr(t, err, "invalid evaluation")
		v.compareLists(t,
			eval.Elements,
			toListBytes(t, vi.EvaluationElement, "evaluation"),
		)

		if v.Mode == VerifiableMode {
			proof := append(eval.Proof.C, eval.Proof.S...) // proof = C || S
			v.compareStrings(t, hex.EncodeToString(proof), vi.Proof.Proof)
		}

		outputs, err := client.Finalize(clientReq, eval, info)
		test.CheckNoErr(t, err, "invalid finalize")
		expectedOutputs := toListBytes(t, vi.Output, "output")
		v.compareLists(t,
			outputs,
			expectedOutputs,
		)

		for j := range inputs {
			output, err := server.FullEvaluate(inputs[j], info)
			test.CheckNoErr(t, err, "invalid full evaluate")
			got := output
			want := expectedOutputs[j]
			if !bytes.Equal(got, want) {
				test.ReportError(t, got, want, v.Name, v.Mode, i, j)
			}

			test.CheckOk(server.VerifyFinalize(inputs[j], info, output), "verify finalize", t)
		}
	}
}

func TestVectors(t *testing.T) {
	// Source of test vectors
	// published: https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf
	// master: https://github.com/cfrg/draft-irtf-cfrg-voprf
	v := readFile(t, "testdata/allVectors.json")

	for i := range v {
		id := v[i].ID
		if !(id == OPRFP256 || id == OPRFP384 || id == OPRFP521) {
			t.Logf(v[i].Name + " not supported yet")
			continue
		}
		t.Run(fmt.Sprintf("Suite%v/Mode%v", id, v[i].Mode), v[i].test)
	}
}
