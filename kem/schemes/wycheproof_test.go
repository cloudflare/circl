package schemes_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/schemes"
)

// ML-KEM test vectors from C2SP/wycheproof (testvectors_v1/mlkem_*.json).
const wycheproofDir = "testdata/wycheproof"

type wycheproofTest struct {
	Seed    test.HexBytes `json:"seed"`
	M       test.HexBytes `json:"m"`
	Ek      test.HexBytes `json:"ek"`
	Dk      test.HexBytes `json:"dk"`
	C       test.HexBytes `json:"c"`
	K       test.HexBytes `json:"K"`
	Result  string        `json:"result"`
	ID      int           `json:"tcId"`
	Comment string        `json:"comment"`
	Flags   []string      `json:"flags"`
}

type wycheproofGroup struct {
	Type         string           `json:"type"`
	ParameterSet string           `json:"parameterSet"`
	Tests        []wycheproofTest `json:"tests"`
}

type wycheproofSet struct {
	Algorithm  string            `json:"algorithm"`
	TestGroups []wycheproofGroup `json:"testGroups"`
}

// A test case runner returns the error with which the scheme rejected an
// input, and reports wrong outputs on t directly, so that a wrong output is
// never mistaken for the rejection an invalid test case expects.
type wycheproofRunner func(*testing.T, kem.Scheme, *wycheproofTest) error

// Invalid test cases leave the expected outputs empty, and the optional K of
// MLKEMDecapsValidationTest may be absent.
func checkBytes(t *testing.T, tc *wycheproofTest, what string, got, want []byte) {
	t.Helper()
	if len(want) != 0 && !bytes.Equal(got, want) {
		t.Errorf("%d: %s does not match: %s", tc.ID, what, tc.Comment)
	}
}

func deriveKeyPair(
	scheme kem.Scheme, seed []byte,
) (kem.PublicKey, kem.PrivateKey, error) {
	// DeriveKeyPair panics on a seed of the wrong size.
	if len(seed) != scheme.SeedSize() {
		return nil, nil, kem.ErrSeedSize
	}
	pk, sk := scheme.DeriveKeyPair(seed)
	return pk, sk, nil
}

// MLKEMTest: derive the key pair from the seed and decapsulate c.
func runKeyGenDecaps(t *testing.T, scheme kem.Scheme, tc *wycheproofTest) error {
	pk, sk, err := deriveKeyPair(scheme, tc.Seed)
	if err != nil {
		return err
	}

	ek, errPk := pk.MarshalBinary()
	test.CheckNoErr(t, errPk, "MarshalBinary()")
	checkBytes(t, tc, "encapsulation key", ek, tc.Ek)

	ss, err := scheme.Decapsulate(sk, tc.C)
	if err != nil {
		return err
	}
	checkBytes(t, tc, "shared key", ss, tc.K)
	return nil
}

// MLKEMEncapsTest: import ek and encapsulate with the randomness m.
func runEncaps(t *testing.T, scheme kem.Scheme, tc *wycheproofTest) error {
	pk, err := scheme.UnmarshalBinaryPublicKey(tc.Ek)
	if err != nil {
		return err
	}

	ct, ss, err := scheme.EncapsulateDeterministically(pk, tc.M)
	if err != nil {
		return err
	}
	checkBytes(t, tc, "ciphertext", ct, tc.C)
	checkBytes(t, tc, "shared key", ss, tc.K)
	return nil
}

// MLKEMDecapsValidationTest: import the expanded dk and decapsulate c.
func runDecapsValidation(t *testing.T, scheme kem.Scheme, tc *wycheproofTest) error {
	sk, err := scheme.UnmarshalBinaryPrivateKey(tc.Dk)
	if err != nil {
		return err
	}

	ek, errPk := sk.Public().MarshalBinary()
	test.CheckNoErr(t, errPk, "MarshalBinary()")
	checkBytes(t, tc, "encapsulation key", ek, tc.Ek)

	ss, err := scheme.Decapsulate(sk, tc.C)
	if err != nil {
		return err
	}
	checkBytes(t, tc, "shared key", ss, tc.K)
	return nil
}

// MLKEMKeyGen: derive the key pair from the seed.
func runKeyGen(t *testing.T, scheme kem.Scheme, tc *wycheproofTest) error {
	pk, sk, err := deriveKeyPair(scheme, tc.Seed)
	if err != nil {
		return err
	}

	ek, errPk := pk.MarshalBinary()
	test.CheckNoErr(t, errPk, "MarshalBinary()")
	checkBytes(t, tc, "encapsulation key", ek, tc.Ek)

	dk, errSk := sk.MarshalBinary()
	test.CheckNoErr(t, errSk, "MarshalBinary()")
	checkBytes(t, tc, "decapsulation key", dk, tc.Dk)
	return nil
}

func wycheproofRunnerFor(groupType string) wycheproofRunner {
	switch groupType {
	case "MLKEMTest":
		return runKeyGenDecaps
	case "MLKEMEncapsTest":
		return runEncaps
	case "MLKEMDecapsValidationTest":
		return runDecapsValidation
	case "MLKEMKeyGen":
		return runKeyGen
	default:
		return nil
	}
}

func runWycheproofFile(t *testing.T, name string) {
	raw, err := test.ReadGzip(path.Join(wycheproofDir, name))
	if err != nil {
		t.Fatalf("ReadGzip(): %v", err)
	}

	var ts wycheproofSet
	if err = json.Unmarshal(raw, &ts); err != nil {
		t.Fatalf("json.Unmarshal(): %v", err)
	}

	for i := range ts.TestGroups {
		tg := &ts.TestGroups[i]

		scheme := schemes.ByName(tg.ParameterSet)
		if scheme == nil {
			t.Fatalf("Can't find scheme %s", tg.ParameterSet)
		}

		run := wycheproofRunnerFor(tg.Type)
		if run == nil {
			t.Fatalf("Unknown test group type: %s", tg.Type)
		}

		for j := range tg.Tests {
			tc := &tg.Tests[j]
			rejected := run(t, scheme, tc)

			switch tc.Result {
			case "valid":
				if rejected != nil {
					t.Errorf("%d: %v: %s", tc.ID, rejected, tc.Comment)
				}
			case "invalid":
				if rejected == nil {
					t.Errorf("%d: expected error: %s", tc.ID, tc.Comment)
				}
			default:
				t.Fatalf("%d: unknown result %q", tc.ID, tc.Result)
			}
		}
	}
}

func TestWycheproof(t *testing.T) {
	entries, err := os.ReadDir(wycheproofDir)
	if err != nil {
		t.Fatal(err)
	}

	files := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json.gz") {
			continue
		}
		files++
		t.Run(entry.Name(), func(t *testing.T) {
			runWycheproofFile(t, entry.Name())
		})
	}

	if files == 0 {
		t.Fatalf("No test vectors found in %s", wycheproofDir)
	}
}
