package oprf

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/zk/dleq"
)

type vector struct {
	Identifier string        `json:"identifier"`
	Mode       Mode          `json:"mode"`
	Hash       string        `json:"hash"`
	PkSm       test.HexBytes `json:"pkSm"`
	SkSm       test.HexBytes `json:"skSm"`
	Seed       test.HexBytes `json:"seed"`
	KeyInfo    test.HexBytes `json:"keyInfo"`
	GroupDST   string        `json:"groupDST"`
	Vectors    []struct {
		Batch             int           `json:"Batch"`
		Blind             CommaHexBytes `json:"Blind"`
		Info              test.HexBytes `json:"Info"`
		BlindedElement    CommaHexBytes `json:"BlindedElement"`
		EvaluationElement CommaHexBytes `json:"EvaluationElement"`
		Proof             struct {
			Proof test.HexBytes `json:"proof"`
			R     test.HexBytes `json:"r"`
		} `json:"Proof"`
		Input  CommaHexBytes `json:"Input"`
		Output CommaHexBytes `json:"Output"`
	} `json:"vectors"`
}

type CommaHexBytes [][]byte

func (b *CommaHexBytes) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	strs := strings.Split(s, ",")
	*b = make([][]byte, len(strs))
	for i := range strs {
		(*b)[i], err = hex.DecodeString(strs[i])
		if err != nil {
			return err
		}
	}

	return nil
}

func (b CommaHexBytes) flatten() []byte {
	out := []byte{0, 0}
	binary.BigEndian.PutUint16(out, uint16(len(b)))
	for i := range b {
		out = append(out, b[i]...)
	}

	return out
}

func toScalar(t *testing.T, g group.Group, rBytes []byte, errMsg string) group.Scalar {
	t.Helper()
	r := g.NewScalar()
	err := r.UnmarshalBinary(rBytes)
	test.CheckNoErr(t, err, errMsg)

	return r
}

func readFile(t *testing.T, fileName string) []vector {
	t.Helper()
	input, err := test.ReadGzip(fileName)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", fileName, err)
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
	test.CheckOk(len(v.Seed) == 32, ErrInvalidSeed.Error(), t)
	privateKey, err := DeriveKey(suite, v.Mode, v.Seed, v.KeyInfo)
	test.CheckNoErr(t, err, "deriving key")
	publicKey := privateKey.Public()

	got, err := privateKey.MarshalBinary()
	test.CheckNoErr(t, err, "serializing private key")
	want := v.SkSm
	v.compareBytes(t, got, want)

	switch v.Mode {
	case VerifiableMode, PartialObliviousMode:
		got, err := publicKey.MarshalBinary()
		test.CheckNoErr(t, err, "serializing public key")
		want := v.PkSm
		v.compareBytes(t, got, want)
	}

	switch v.Mode {
	case BaseMode:
		s = NewServer(suite, privateKey)
		c = NewClient(suite)
	case VerifiableMode:
		s = NewVerifiableServer(suite, privateKey)
		c = NewVerifiableClient(suite, publicKey)
	case PartialObliviousMode:
		var info []byte
		s = &s1{NewPartialObliviousServer(suite, privateKey), info}
		c = &c1{NewPartialObliviousClient(suite, publicKey), info}
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
			ss := server.(*s1)
			cc := client.(*c1)
			ss.info = vi.Info
			cc.info = vi.Info
		}

		blinds := make([]Blind, len(vi.Blind))
		for j := range vi.Blind {
			blinds[j] = params.group.NewScalar()
			err := blinds[j].UnmarshalBinary(vi.Blind[j])
			test.CheckNoErr(t, err, "invalid blind")
		}

		finData, evalReq, err := client.blind(vi.Input, blinds)
		test.CheckNoErr(t, err, "invalid client request")
		evalReqBytes, err := elementsMarshalBinary(params.group, evalReq.Elements)
		test.CheckNoErr(t, err, "bad serialization")
		v.compareBytes(t, evalReqBytes, vi.BlindedElement.flatten())

		eval, err := server.Evaluate(evalReq)
		test.CheckNoErr(t, err, "invalid evaluation")
		elemBytes, err := elementsMarshalBinary(params.group, eval.Elements)
		test.CheckNoErr(t, err, "invalid evaluations marshaling")
		v.compareBytes(t, elemBytes, vi.EvaluationElement.flatten())

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
			v.compareBytes(t, proofBytes, vi.Proof.Proof)
		}

		outputs, err := client.Finalize(finData, eval)
		test.CheckNoErr(t, err, "invalid finalize")
		v.compareLists(t, outputs, vi.Output)

		for j := range vi.Input {
			output, err := server.FullEvaluate(vi.Input[j])
			test.CheckNoErr(t, err, "invalid full evaluate")
			got := output
			want := vi.Output[j]
			if !bytes.Equal(got, want) {
				test.ReportError(t, got, want, v.Identifier, v.Mode, i, j)
			}

			test.CheckOk(server.VerifyFinalize(vi.Input[j], output), "verify finalize", t)
		}
	}
}

func TestVectors(t *testing.T) {
	// RFC-9497 published at https://www.rfc-editor.org/info/rfc9497
	// Test vectors at https://github.com/cfrg/draft-irtf-cfrg-voprf
	v := readFile(t, "testdata/rfc9497.json.gz")

	for i := range v {
		suite, err := GetSuite(v[i].Identifier)
		if err != nil {
			t.Log(v[i].Identifier + " not supported yet")
			continue
		}
		t.Run(fmt.Sprintf("%v/Mode%v", suite, v[i].Mode), v[i].test)
	}
}
