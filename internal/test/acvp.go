package test

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// ACVP is a decoded pair of ACVP test vector files: the prompt file, holding
// the test groups, and the expectedResults file, holding the results indexed
// by test case id.
//
// Vectors come from https://github.com/usnistgov/ACVP-Server, where every
// algorithm directory pairs a prompt.json with an expectedResults.json.
type ACVP struct {
	// Groups are the raw test groups of the prompt file. Unmarshal each one
	// into whatever shape the algorithm under test expects.
	Groups []json.RawMessage

	results map[int]json.RawMessage
}

// ReadACVP reads the gzipped prompt and expectedResults files of the ACVP
// test vector directory dir.
func ReadACVP(t testing.TB, dir string) *ACVP {
	t.Helper()

	acvp := &ACVP{
		Groups:  readACVPGroups(t, filepath.Join(dir, "prompt.json.gz")),
		results: make(map[int]json.RawMessage),
	}

	for _, rawGroup := range readACVPGroups(t, filepath.Join(dir, "expectedResults.json.gz")) {
		var group struct {
			Tests []json.RawMessage `json:"tests"`
		}
		if err := json.Unmarshal(rawGroup, &group); err != nil {
			t.Fatal(err)
		}

		for _, rawTest := range group.Tests {
			var abstractTest struct {
				TcID int `json:"tcId"`
			}
			if err := json.Unmarshal(rawTest, &abstractTest); err != nil {
				t.Fatal(err)
			}
			if _, exists := acvp.results[abstractTest.TcID]; exists {
				t.Fatalf("Duplicate test id: %d", abstractTest.TcID)
			}
			acvp.results[abstractTest.TcID] = rawTest
		}
	}

	return acvp
}

// Result unmarshals the expected result of test case tcID into result.
func (a *ACVP) Result(t testing.TB, tcID int, result interface{}) {
	t.Helper()

	rawResult, ok := a.results[tcID]
	if !ok {
		t.Fatalf("Missing result: %d", tcID)
	}
	if err := json.Unmarshal(rawResult, result); err != nil {
		t.Fatal(err)
	}
}

func readACVPGroups(t testing.TB, path string) []json.RawMessage {
	t.Helper()

	buf, err := ReadGzip(path)
	if err != nil {
		t.Fatal(err)
	}

	var file struct {
		TestGroups []json.RawMessage `json:"testGroups"`
	}
	if err := json.Unmarshal(buf, &file); err != nil {
		t.Fatal(err)
	}

	return file.TestGroups
}
