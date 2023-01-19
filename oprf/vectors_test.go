package oprf

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/zk/dleq"
)

type vector struct {
	Identifier string `json:"identifier"`
	Mode       Mode   `json:"mode"`
	Hash       string `json:"hash"`
	PkSm       string `json:"pkSm"`
	SkSm       string `json:"skSm"`
	Seed       string `json:"seed"`
	KeyInfo    string `json:"keyInfo"`
	GroupDST   string `json:"groupDST"`
	Vectors    []struct {
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
	t.Helper()
	bytes, err := hex.DecodeString(s)
	test.CheckNoErr(t, err, "decoding "+errMsg)

	return bytes
}

func toListBytes(t *testing.T, s, errMsg string) [][]byte {
	t.Helper()
	strs := strings.Split(s, ",")
	out := make([][]byte, len(strs))
	for i := range strs {
		out[i] = toBytes(t, strs[i], errMsg)
	}

	return out
}

func flattenList(t *testing.T, s, errMsg string) []byte {
	t.Helper()
	strs := strings.Split(s, ",")
	out := []byte{0, 0}
	binary.BigEndian.PutUint16(out, uint16(len(strs)))
	for i := range strs {
		out = append(out, toBytes(t, strs[i], errMsg)...)
	}

	return out
}

func toScalar(t *testing.T, g group.Group, s, errMsg string) group.Scalar {
	t.Helper()
	r := g.NewScalar()
	rBytes := toBytes(t, s, errMsg)
	err := r.UnmarshalBinary(rBytes)
	test.CheckNoErr(t, err, errMsg)

	return r
}

func readFile(t *testing.T, fileName string) []vector {
	t.Helper()
	jsonFile, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", fileName, err)
	}
	defer jsonFile.Close()
	input, err := io.ReadAll(jsonFile)
	if err != nil {
		t.Fatalf("File %v can not be read. Error: %v", fileName, err)
	}

	var v []vector
	err = json.Unmarshal(input, &v)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", fileName, err)
	}

	return v
}

func (v *vector) SetUpParties(t *testing.T) (id params, s commonServer, c commonClient) {
	suite, err := GetSuite(v.Identifier)
	test.CheckNoErr(t, err, "suite id")
	seed := toBytes(t, v.Seed, "seed for key derivation")
	keyInfo := toBytes(t, v.KeyInfo, "info for key derivation")
	privateKey, err := DeriveKey(suite, v.Mode, seed, keyInfo)
	test.CheckNoErr(t, err, "deriving key")

	got, err := privateKey.MarshalBinary()
	test.CheckNoErr(t, err, "serializing private key")
	want := toBytes(t, v.SkSm, "private key")
	v.compareBytes(t, got, want)

	switch v.Mode {
	case BaseMode:
		s = NewServer(suite, privateKey)
		c = NewClient(suite)
	case VerifiableMode:
		s = NewVerifiableServer(suite, privateKey)
		c = NewVerifiableClient(suite, s.PublicKey())
	case PartialObliviousMode:
		var info []byte
		s = &s1{NewPartialObliviousServer(suite, privateKey), info}
		c = &c1{NewPartialObliviousClient(suite, s.PublicKey()), info}
	}

	return suite.(params), s, c
}

func (v *vector) compareLists(t *testing.T, got, want [][]byte) {
	t.Helper()
	for i := range got {
		if !bytes.Equal(got[i], want[i]) {
			test.ReportError(t, got[i], want[i], v.Identifier, v.Mode, i)
		}
	}
}

func (v *vector) compareBytes(t *testing.T, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		test.ReportError(t, got, want, v.Identifier, v.Mode)
	}
}

func (v *vector) test(t *testing.T) {
	params, server, client := v.SetUpParties(t)

	for i, vi := range v.Vectors {
		if v.Mode == PartialObliviousMode {
			info := toBytes(t, vi.Info, "info")
			ss := server.(*s1)
			cc := client.(*c1)
			ss.info = info
			cc.info = info
		}

		inputs := toListBytes(t, vi.Input, "input")
		blindsBytes := toListBytes(t, vi.Blind, "blind")

		blinds := make([]Blind, len(blindsBytes))
		for j := range blindsBytes {
			blinds[j] = params.group.NewScalar()
			err := blinds[j].UnmarshalBinary(blindsBytes[j])
			test.CheckNoErr(t, err, "invalid blind")
		}

		finData, evalReq, err := client.blind(inputs, blinds)
		test.CheckNoErr(t, err, "invalid client request")
		evalReqBytes, err := elementsMarshalBinary(params.group, evalReq.Elements)
		test.CheckNoErr(t, err, "bad serialization")
		v.compareBytes(t, evalReqBytes, flattenList(t, vi.BlindedElement, "blindedElement"))

		eval, err := server.Evaluate(evalReq)
		test.CheckNoErr(t, err, "invalid evaluation")
		elemBytes, err := elementsMarshalBinary(params.group, eval.Elements)
		test.CheckNoErr(t, err, "invalid evaluations marshaling")
		v.compareBytes(t, elemBytes, flattenList(t, vi.EvaluationElement, "evaluation"))

		if v.Mode == VerifiableMode || v.Mode == PartialObliviousMode {
			randomness := toScalar(t, params.group, vi.Proof.R, "invalid proof random scalar")
			var proof encoding.BinaryMarshaler
			switch v.Mode {
			case VerifiableMode:
				ss := server.(VerifiableServer)
				prover := dleq.Prover{Params: ss.getDLEQParams()}
				proof, err = prover.ProveBatchWithRandomness(
					ss.privateKey.k,
					ss.params.group.Generator(),
					server.PublicKey().e,
					evalReq.Elements,
					eval.Elements,
					randomness)
			case PartialObliviousMode:
				ss := server.(*s1)
				keyProof, _, _ := ss.secretFromInfo(ss.info)
				prover := dleq.Prover{Params: ss.getDLEQParams()}
				proof, err = prover.ProveBatchWithRandomness(
					keyProof,
					ss.params.group.Generator(),
					ss.params.group.NewElement().MulGen(keyProof),
					eval.Elements,
					evalReq.Elements,
					randomness)
			}
			test.CheckNoErr(t, err, "failed proof generation")
			proofBytes, errr := proof.MarshalBinary()
			test.CheckNoErr(t, errr, "failed proof marshaling")
			v.compareBytes(t, proofBytes, toBytes(t, vi.Proof.Proof, "proof"))
		}

		outputs, err := client.Finalize(finData, eval)
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
				test.ReportError(t, got, want, v.Identifier, v.Mode, i, j)
			}

			test.CheckOk(server.VerifyFinalize(inputs[j], output), "verify finalize", t)
		}
	}
}

func TestVectors(t *testing.T) {
	// Draft published at https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-10
	// Test vectors at https://github.com/cfrg/draft-irtf-cfrg-voprf
	// Version supported: v10
	v := readFile(t, "testdata/allVectors.json")

	for i := range v {
		suite, err := GetSuite(v[i].Identifier)
		if err != nil {
			t.Logf(v[i].Identifier + " not supported yet")
			continue
		}
		t.Run(fmt.Sprintf("%v/Mode%v", suite, v[i].Mode), v[i].test)
	}
}
