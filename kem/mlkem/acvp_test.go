package mlkem

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/cloudflare/circl/kem/schemes"
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
		"encapDecap",
	} {
		t.Run(sub, func(t *testing.T) {
			testACVP(t, sub)
		})
	}
}

// nolint:funlen,gocyclo
func testACVP(t *testing.T, sub string) {
	buf, err := readGzip("testdata/ML-KEM-" + sub + "-FIPS203/prompt.json.gz")
	if err != nil {
		t.Fatal(err)
	}

	var prompt struct {
		TestGroups []json.RawMessage `json:"testGroups"`
	}

	if err = json.Unmarshal(buf, &prompt); err != nil {
		t.Fatal(err)
	}

	buf, err = readGzip("testdata/ML-KEM-" + sub + "-FIPS203/expectedResults.json.gz")
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
					TcID int      `json:"tcId"`
					Z    HexBytes `json:"z"`
					D    HexBytes `json:"d"`
				}
			}
			if err := json.Unmarshal(rawGroup, &group); err != nil {
				t.Fatal(err)
			}

			scheme := schemes.ByName(group.ParameterSet)
			if scheme == nil {
				t.Fatalf("No such scheme: %s", group.ParameterSet)
			}

			for _, test := range group.Tests {
				var result struct {
					Ek HexBytes `json:"ek"`
					Dk HexBytes `json:"dk"`
				}
				rawResult, ok := rawResults[test.TcID]
				if !ok {
					t.Fatalf("Missing result: %d", test.TcID)
				}
				if err := json.Unmarshal(rawResult, &result); err != nil {
					t.Fatal(err)
				}

				var seed [64]byte
				copy(seed[:], test.D)
				copy(seed[32:], test.Z)

				ek, dk := scheme.DeriveKeyPair(seed[:])

				ek2, err := scheme.UnmarshalBinaryPublicKey(result.Ek)
				if err != nil {
					t.Fatalf("tc=%d: %v", test.TcID, err)
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
					TcID int      `json:"tcId"`
					Ek   HexBytes `json:"ek"`
					M    HexBytes `json:"m"`
				}
			}
			if err := json.Unmarshal(rawGroup, &group); err != nil {
				t.Fatal(err)
			}

			scheme := schemes.ByName(group.ParameterSet)
			if scheme == nil {
				t.Fatalf("No such scheme: %s", group.ParameterSet)
			}

			for _, test := range group.Tests {
				var result struct {
					C HexBytes `json:"c"`
					K HexBytes `json:"k"`
				}
				rawResult, ok := rawResults[test.TcID]
				if !ok {
					t.Fatalf("Missing result: %d", test.TcID)
				}
				if err := json.Unmarshal(rawResult, &result); err != nil {
					t.Fatal(err)
				}

				ek, err := scheme.UnmarshalBinaryPublicKey(test.Ek)
				if err != nil {
					t.Fatal(err)
				}

				ct, ss, err := scheme.EncapsulateDeterministically(ek, test.M)
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
				TgID         int      `json:"tgId"`
				ParameterSet string   `json:"parameterSet"`
				Dk           HexBytes `json:"dk"`
				Tests        []struct {
					TcID int      `json:"tcId"`
					C    HexBytes `json:"c"`
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

			for _, test := range group.Tests {
				var result struct {
					K HexBytes `json:"k"`
				}
				rawResult, ok := rawResults[test.TcID]
				if !ok {
					t.Fatalf("Missing rawResult: %d", test.TcID)
				}
				if err := json.Unmarshal(rawResult, &result); err != nil {
					t.Fatal(err)
				}

				ss, err := scheme.Decapsulate(dk, test.C)
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
