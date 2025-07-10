// Code generated from acvp.templ.go. DO NOT EDIT.

package mldsa87

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

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
	buf, err := test.ReadGzip("../testdata/ML-DSA-" + sub + "-FIPS204/prompt.json.gz")
	if err != nil {
		t.Fatal(err)
	}

	var prompt struct {
		TestGroups []json.RawMessage `json:"testGroups"`
	}

	if err = json.Unmarshal(buf, &prompt); err != nil {
		t.Fatal(err)
	}

	buf, err = test.ReadGzip("../testdata/ML-DSA-" + sub + "-FIPS204/expectedResults.json.gz")
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
					TcID int           `json:"tcId"`
					Seed test.HexBytes `json:"seed"`
				}
			}
			if err := json.Unmarshal(rawGroup, &group); err != nil {
				t.Fatal(err)
			}

			if group.ParameterSet != scheme.Name() {
				continue
			}

			for _, tst := range group.Tests {
				var result struct {
					Pk test.HexBytes `json:"pk"`
					Sk test.HexBytes `json:"sk"`
				}
				rawResult, ok := rawResults[tst.TcID]
				if !ok {
					t.Fatalf("Missing result: %d", tst.TcID)
				}
				if err := json.Unmarshal(rawResult, &result); err != nil {
					t.Fatal(err)
				}

				pk, sk := scheme.DeriveKey(tst.Seed)

				pk2, err := scheme.UnmarshalBinaryPublicKey(result.Pk)
				if err != nil {
					t.Fatalf("tc=%d: %v", tst.TcID, err)
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
					TcID    int           `json:"tcId"`
					Sk      test.HexBytes `json:"sk"`
					Message test.HexBytes `json:"message"`
					Rnd     test.HexBytes `json:"rnd"`
				}
			}
			if err := json.Unmarshal(rawGroup, &group); err != nil {
				t.Fatal(err)
			}

			if group.ParameterSet != scheme.Name() {
				continue
			}

			for _, tst := range group.Tests {
				var result struct {
					Signature test.HexBytes `json:"signature"`
				}
				rawResult, ok := rawResults[tst.TcID]
				if !ok {
					t.Fatalf("Missing result: %d", tst.TcID)
				}
				if err := json.Unmarshal(rawResult, &result); err != nil {
					t.Fatal(err)
				}

				sk, err := scheme.UnmarshalBinaryPrivateKey(tst.Sk)
				if err != nil {
					t.Fatal(err)
				}

				var rnd [32]byte
				if !group.Deterministic {
					copy(rnd[:], tst.Rnd)
				}

				sig2 := sk.(*PrivateKey).unsafeSignInternal(tst.Message, rnd)

				if !bytes.Equal(sig2, result.Signature) {
					t.Fatalf("signature doesn't match: %x ≠ %x",
						sig2, result.Signature)
				}
			}
		case abstractGroup.TestType == "AFT" && sub == "sigVer":
			var group struct {
				TgID         int           `json:"tgId"`
				ParameterSet string        `json:"parameterSet"`
				Pk           test.HexBytes `json:"pk"`
				Tests        []struct {
					TcID      int           `json:"tcId"`
					Message   test.HexBytes `json:"message"`
					Signature test.HexBytes `json:"signature"`
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

			for _, tst := range group.Tests {
				var result struct {
					TestPassed bool `json:"testPassed"`
				}
				rawResult, ok := rawResults[tst.TcID]
				if !ok {
					t.Fatalf("Missing result: %d", tst.TcID)
				}
				if err := json.Unmarshal(rawResult, &result); err != nil {
					t.Fatal(err)
				}

				passed2 := unsafeVerifyInternal(pk.(*PublicKey), tst.Message, tst.Signature)
				if passed2 != result.TestPassed {
					t.Fatalf("verification %v ≠ %v", passed2, result.TestPassed)
				}
			}
		default:
			t.Fatalf("unknown type %s for %s", abstractGroup.TestType, sub)
		}
	}
}
