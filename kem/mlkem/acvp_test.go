package mlkem

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/kem/schemes"
)

func TestACVP(t *testing.T) {
	for _, sub := range []string{
		"keyGen",
		"encapDecap",
	} {
		t.Run(sub, func(t *testing.T) {
			testACVP(t, sub)
		})
	}
}

// nolint:funlen,gocyclo
func testACVP(t *testing.T, sub string) {
	buf, err := test.ReadGzip("testdata/ML-KEM-" + sub + "-FIPS203/prompt.json.gz")
	if err != nil {
		t.Fatal(err)
	}

	var prompt struct {
		TestGroups []json.RawMessage `json:"testGroups"`
	}

	if err = json.Unmarshal(buf, &prompt); err != nil {
		t.Fatal(err)
	}

	buf, err = test.ReadGzip("testdata/ML-KEM-" + sub + "-FIPS203/expectedResults.json.gz")
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
					Z    test.HexBytes `json:"z"`
					D    test.HexBytes `json:"d"`
				}
			}
			if err := json.Unmarshal(rawGroup, &group); err != nil {
				t.Fatal(err)
			}

			scheme := schemes.ByName(group.ParameterSet)
			if scheme == nil {
				t.Fatalf("No such scheme: %s", group.ParameterSet)
			}

			for _, tst := range group.Tests {
				var result struct {
					Ek test.HexBytes `json:"ek"`
					Dk test.HexBytes `json:"dk"`
				}
				rawResult, ok := rawResults[tst.TcID]
				if !ok {
					t.Fatalf("Missing result: %d", tst.TcID)
				}
				if err := json.Unmarshal(rawResult, &result); err != nil {
					t.Fatal(err)
				}

				var seed [64]byte
				copy(seed[:], tst.D)
				copy(seed[32:], tst.Z)

				ek, dk := scheme.DeriveKeyPair(seed[:])

				ek2, err := scheme.UnmarshalBinaryPublicKey(result.Ek)
				if err != nil {
					t.Fatalf("tc=%d: %v", tst.TcID, err)
				}
				dk2, err := scheme.UnmarshalBinaryPrivateKey(result.Dk)
				if err != nil {
					t.Fatal(err)
				}

				if !dk.Equal(dk2) {
					t.Fatal("dk does not match")
				}
				if !ek.Equal(ek2) {
					t.Fatal("ek does not match")
				}
			}
		case abstractGroup.TestType == "AFT" && sub == "encapDecap":
			var group struct {
				TgID         int    `json:"tgId"`
				ParameterSet string `json:"parameterSet"`
				Tests        []struct {
					TcID int           `json:"tcId"`
					Ek   test.HexBytes `json:"ek"`
					M    test.HexBytes `json:"m"`
				}
			}
			if err := json.Unmarshal(rawGroup, &group); err != nil {
				t.Fatal(err)
			}

			scheme := schemes.ByName(group.ParameterSet)
			if scheme == nil {
				t.Fatalf("No such scheme: %s", group.ParameterSet)
			}

			for _, tst := range group.Tests {
				var result struct {
					C test.HexBytes `json:"c"`
					K test.HexBytes `json:"k"`
				}
				rawResult, ok := rawResults[tst.TcID]
				if !ok {
					t.Fatalf("Missing result: %d", tst.TcID)
				}
				if err := json.Unmarshal(rawResult, &result); err != nil {
					t.Fatal(err)
				}

				ek, err := scheme.UnmarshalBinaryPublicKey(tst.Ek)
				if err != nil {
					t.Fatal(err)
				}

				ct, ss, err := scheme.EncapsulateDeterministically(ek, tst.M)
				if err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(ct, result.C) {
					t.Fatalf("ciphertext doesn't match: %x ≠ %x", ct, result.C)
				}
				if !bytes.Equal(ss, result.K) {
					t.Fatalf("shared secret doesn't match: %x ≠ %x", ss, result.K)
				}
			}
		case abstractGroup.TestType == "VAL" && sub == "encapDecap":
			var group struct {
				TgID         int           `json:"tgId"`
				ParameterSet string        `json:"parameterSet"`
				Dk           test.HexBytes `json:"dk"`
				Tests        []struct {
					TcID int           `json:"tcId"`
					C    test.HexBytes `json:"c"`
				}
			}
			if err := json.Unmarshal(rawGroup, &group); err != nil {
				t.Fatal(err)
			}

			scheme := schemes.ByName(group.ParameterSet)
			if scheme == nil {
				t.Fatalf("No such scheme: %s", group.ParameterSet)
			}

			dk, err := scheme.UnmarshalBinaryPrivateKey(group.Dk)
			if err != nil {
				t.Fatal(err)
			}

			for _, tst := range group.Tests {
				var result struct {
					K test.HexBytes `json:"k"`
				}
				rawResult, ok := rawResults[tst.TcID]
				if !ok {
					t.Fatalf("Missing rawResult: %d", tst.TcID)
				}
				if err := json.Unmarshal(rawResult, &result); err != nil {
					t.Fatal(err)
				}

				ss, err := scheme.Decapsulate(dk, tst.C)
				if err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(ss, result.K) {
					t.Fatalf("shared secret doesn't match: %x ≠ %x", ss, result.K)
				}
			}
		default:
			t.Fatalf("unknown type %s for %s", abstractGroup.TestType, sub)
		}
	}
}
