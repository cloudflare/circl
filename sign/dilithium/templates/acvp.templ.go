// +build ignore
// The previous line (and this one up to the warning below) is removed by the
// template generator.

// Code generated from acvp.templ.go. DO NOT EDIT.

package {{.Pkg}}

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"
)

// []byte but is encoded in hex for JSON
type HexBytes []byte

func (b HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(b))
}

func (b *HexBytes) UnmarshalJSON(data []byte) (err error) {
	var s string
	if err = json.Unmarshal(data, &s); err != nil {
		return err
	}
	*b, err = hex.DecodeString(s)
	return err
}

func gunzip(in []byte) ([]byte, error) {
	buf := bytes.NewBuffer(in)
	r, err := gzip.NewReader(buf)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func readGzip(path string) ([]byte, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return gunzip(buf)
}

func TestACVP(t *testing.T) {
	for _, sub := range []string{
		"keyGen",
		"sigGen",
		"sigVer",
	} {
		t.Run(sub, func(t *testing.T) {
			testACVP(t, sub)
		})
	}
}

// nolint:funlen,gocyclo
func testACVP(t *testing.T, sub string) {
	buf, err := readGzip("../testdata/ML-DSA-" + sub + "-FIPS204/prompt.json.gz")
	if err != nil {
		t.Fatal(err)
	}

	var prompt struct {
		TestGroups []json.RawMessage `json:"testGroups"`
	}

	if err = json.Unmarshal(buf, &prompt); err != nil {
		t.Fatal(err)
	}

	buf, err = readGzip("../testdata/ML-DSA-" + sub + "-FIPS204/expectedResults.json.gz")
	if err != nil {
		t.Fatal(err)
	}

	var results struct {
		TestGroups []json.RawMessage `json:"testGroups"`
	}

	if err := json.Unmarshal(buf, &results); err != nil {
		t.Fatal(err)
	}

	rawResults := make(map[int]json.RawMessage)

	for _, rawGroup := range results.TestGroups {
		var abstractGroup struct {
			Tests []json.RawMessage `json:"tests"`
		}
		if err := json.Unmarshal(rawGroup, &abstractGroup); err != nil {
			t.Fatal(err)
		}
		for _, rawTest := range abstractGroup.Tests {
			var abstractTest struct {
				TcID int `json:"tcId"`
			}
			if err := json.Unmarshal(rawTest, &abstractTest); err != nil {
				t.Fatal(err)
			}
			if _, exists := rawResults[abstractTest.TcID]; exists {
				t.Fatalf("Duplicate test id: %d", abstractTest.TcID)
			}
			rawResults[abstractTest.TcID] = rawTest
		}
	}

	scheme := Scheme()

	for _, rawGroup := range prompt.TestGroups {
		var abstractGroup struct {
			TestType string `json:"testType"`
		}
		if err := json.Unmarshal(rawGroup, &abstractGroup); err != nil {
			t.Fatal(err)
		}
		switch {
		case abstractGroup.TestType == "AFT" && sub == "keyGen":
			var group struct {
				TgID         int    `json:"tgId"`
				ParameterSet string `json:"parameterSet"`
				Tests        []struct {
					TcID int      `json:"tcId"`
					Seed HexBytes `json:"seed"`
				}
			}
			if err := json.Unmarshal(rawGroup, &group); err != nil {
				t.Fatal(err)
			}

			if group.ParameterSet != scheme.Name() {
				continue
			}

			for _, test := range group.Tests {
				var result struct {
					Pk HexBytes `json:"pk"`
					Sk HexBytes `json:"sk"`
				}
				rawResult, ok := rawResults[test.TcID]
				if !ok {
					t.Fatalf("Missing result: %d", test.TcID)
				}
				if err := json.Unmarshal(rawResult, &result); err != nil {
					t.Fatal(err)
				}

				pk, sk := scheme.DeriveKey(test.Seed)

				pk2, err := scheme.UnmarshalBinaryPublicKey(result.Pk)
				if err != nil {
					t.Fatalf("tc=%d: %v", test.TcID, err)
				}
				sk2, err := scheme.UnmarshalBinaryPrivateKey(result.Sk)
				if err != nil {
					t.Fatal(err)
				}

				if !pk.Equal(pk2) {
					t.Fatal("pk does not match")
				}
				if !sk.Equal(sk2) {
					t.Fatal("sk does not match")
				}
			}
		case abstractGroup.TestType == "AFT" && sub == "sigGen":
			var group struct {
				TgID          int    `json:"tgId"`
				ParameterSet  string `json:"parameterSet"`
				Deterministic bool   `json:"deterministic"`
				Tests         []struct {
					TcID    int      `json:"tcId"`
					Sk      HexBytes `json:"sk"`
					Message HexBytes `json:"message"`
					Rnd     HexBytes `json:"rnd"`
				}
			}
			if err := json.Unmarshal(rawGroup, &group); err != nil {
				t.Fatal(err)
			}

			if group.ParameterSet != scheme.Name() {
				continue
			}

			for _, test := range group.Tests {
				var result struct {
					Signature HexBytes `json:"signature"`
				}
				rawResult, ok := rawResults[test.TcID]
				if !ok {
					t.Fatalf("Missing result: %d", test.TcID)
				}
				if err := json.Unmarshal(rawResult, &result); err != nil {
					t.Fatal(err)
				}

				sk, err := scheme.UnmarshalBinaryPrivateKey(test.Sk)
				if err != nil {
					t.Fatal(err)
				}

				var rnd [32]byte
				if !group.Deterministic {
					copy(rnd[:], test.Rnd)
				}

				sig2 := sk.(*PrivateKey).unsafeSignInternal(test.Message, rnd)

				if !bytes.Equal(sig2, result.Signature) {
					t.Fatalf("signature doesn't match: %x ≠ %x",
						sig2, result.Signature)
				}
			}
		case abstractGroup.TestType == "AFT" && sub == "sigVer":
			var group struct {
				TgID         int      `json:"tgId"`
				ParameterSet string   `json:"parameterSet"`
				Pk           HexBytes `json:"pk"`
				Tests        []struct {
					TcID      int      `json:"tcId"`
					Message   HexBytes `json:"message"`
					Signature HexBytes `json:"signature"`
				}
			}
			if err := json.Unmarshal(rawGroup, &group); err != nil {
				t.Fatal(err)
			}

			if group.ParameterSet != scheme.Name() {
				continue
			}

			pk, err := scheme.UnmarshalBinaryPublicKey(group.Pk)
			if err != nil {
				t.Fatal(err)
			}

			for _, test := range group.Tests {
				var result struct {
					TestPassed bool `json:"testPassed"`
				}
				rawResult, ok := rawResults[test.TcID]
				if !ok {
					t.Fatalf("Missing result: %d", test.TcID)
				}
				if err := json.Unmarshal(rawResult, &result); err != nil {
					t.Fatal(err)
				}

				passed2 := unsafeVerifyInternal(pk.(*PublicKey), test.Message, test.Signature)
				if passed2 != result.TestPassed {
					t.Fatalf("verification %v ≠ %v", passed2, result.TestPassed)
				}
			}
		default:
			t.Fatalf("unknown type %s for %s", abstractGroup.TestType, sub)
		}
	}
}
