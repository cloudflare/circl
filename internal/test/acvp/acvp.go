// Package acvp provides shared helpers for ACVP test vector parsing.
package acvp

import (
	"encoding/json"
	"path"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

// LoadVectors loads ACVP prompt and expectedResults files from the given
// directory (containing prompt.json.gz and expectedResults.json.gz).
//
// It returns the prompt's raw test groups and a map keyed by tcId mapping
// to the raw test JSON from expectedResults.
func LoadVectors(t *testing.T, dir string) (groups []json.RawMessage, results map[int]json.RawMessage) {
	t.Helper()

	buf, err := test.ReadGzip(path.Join(dir, "prompt.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	var prompt struct {
		TestGroups []json.RawMessage `json:"testGroups"`
	}
	if err := json.Unmarshal(buf, &prompt); err != nil {
		t.Fatal(err)
	}

	buf, err = test.ReadGzip(path.Join(dir, "expectedResults.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	var expected struct {
		TestGroups []json.RawMessage `json:"testGroups"`
	}
	if err := json.Unmarshal(buf, &expected); err != nil {
		t.Fatal(err)
	}

	results = make(map[int]json.RawMessage)
	for _, rawGroup := range expected.TestGroups {
		var group struct {
			Tests []json.RawMessage `json:"tests"`
		}
		if err := json.Unmarshal(rawGroup, &group); err != nil {
			t.Fatal(err)
		}
		for _, rawTest := range group.Tests {
			var tst struct {
				TcID int `json:"tcId"`
			}
			if err := json.Unmarshal(rawTest, &tst); err != nil {
				t.Fatal(err)
			}
			if _, exists := results[tst.TcID]; exists {
				t.Fatalf("duplicate test id: %d", tst.TcID)
			}
			results[tst.TcID] = rawTest
		}
	}

	return prompt.TestGroups, results
}
