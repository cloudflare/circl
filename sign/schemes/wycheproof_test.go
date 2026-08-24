package schemes

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/sign"
)

const testDir = "testdata/wycheproof"

type Test struct {
	Msg     test.HexBytes `json:"msg"`
	Mu      test.HexBytes `json:"mu"`
	Rnd     test.HexBytes `json:"rnd"`
	Sig     test.HexBytes `json:"sig"`
	Result  string        `json:"result"`
	Ctx     test.HexBytes `json:"ctx"`
	ID      int           `json:"tcId"`
	Comment string        `json:"comment"`
	Flags   []string      `json:"flags"`
}

type TestGroup struct {
	PrivateKey  test.HexBytes `json:"privateKey"`
	PrivateSeed test.HexBytes `json:"privateSeed"`
	PublicKey   test.HexBytes `json:"publicKey"`
	Tests       []Test        `json:"tests"`
	Type        string        `json:"type"`
}

type TestSet struct {
	Algorithm  string      `json:"algorithm"`
	TestGroups []TestGroup `json:"testGroups"`
}

// Implemented by the ML-DSA private keys.
type muComputer interface {
	ComputeMu(msg, ctx []byte) (*[64]byte, error)
}

// Checks the μ pinned by tc. A missing μ means computing it is expected to
// fail; see doc/mldsa.md in C2SP/wycheproof.
func checkMu(t *testing.T, sk sign.PrivateKey, tc *Test) {
	mc, ok := sk.(muComputer)
	if !ok || slices.Contains(tc.Flags, "Internal") {
		return
	}

	mu, err := mc.ComputeMu(tc.Msg, tc.Ctx)
	switch {
	case tc.Mu == nil:
		if err == nil {
			t.Errorf("%d: expected ComputeMu() to fail", tc.ID)
		}
	case err != nil:
		t.Errorf("%d: ComputeMu(): %v", tc.ID, err)
	case !bytes.Equal(mu[:], tc.Mu):
		t.Errorf("%d: μ does not match", tc.ID)
	}
}

// Signs tc, both from the message and from the μ pinned by tc, checking the
// two agree. Testcases flagged Internal only provide a μ.
func signTestCase(sk sign.PrivateKey, tc *Test) ([]byte, error) {
	var sig []byte

	if !slices.Contains(tc.Flags, "Internal") {
		opts := sign.TestingSignerOpts{Randomness: tc.Rnd}
		opts.Context = string(tc.Ctx)

		var err error
		if sig, err = sk.Sign(nil, tc.Msg, opts); err != nil {
			return nil, err
		}
	}

	if tc.Mu == nil {
		return sig, nil
	}

	opts := sign.TestingSignerOpts{Randomness: tc.Rnd}
	opts.Hash = sign.MLDSAMu

	sigMu, err := sk.Sign(nil, tc.Mu, opts)
	if err != nil {
		return nil, err
	}

	if sig != nil && !bytes.Equal(sig, sigMu) {
		return nil, errors.New("signing with and without external μ disagree")
	}

	return sigMu, nil
}

func runSignGroup(t *testing.T, scheme sign.Scheme, tg *TestGroup) {
	var (
		sk    sign.PrivateKey
		skErr error
	)

	switch {
	case (tg.PrivateKey == nil) == (tg.PrivateSeed == nil):
		t.Fatal("Exactly one of private key and seed must be set")
	case tg.PrivateSeed != nil:
		if len(tg.PrivateSeed) == scheme.SeedSize() {
			_, sk = scheme.DeriveKey(tg.PrivateSeed)
		} else {
			skErr = sign.ErrSeedSize
		}
	default:
		sk, skErr = scheme.UnmarshalBinaryPrivateKey(tg.PrivateKey)
	}

	// The vectors also pin the public key belonging to the private key.
	if sk != nil && tg.PublicKey != nil {
		pk, err := sk.Public().(sign.PublicKey).MarshalBinary()
		test.CheckNoErr(t, err, "MarshalBinary()")
		if !bytes.Equal(pk, tg.PublicKey) {
			t.Fatal("Derived public key does not match")
		}
	}

	for i := range tg.Tests {
		tc := &tg.Tests[i]

		// TODO The standards don't require rejecting private keys
		// 		with out of range s1/s2. Pending discussion on whether
		//      we should reject them, we're skipping these testcases.
		if slices.Contains(tc.Flags, "InvalidPrivateKey") {
			continue
		}

		if skErr != nil {
			if tc.Result != "invalid" { //nolint:goconst
				t.Fatalf("%d: couldn't parse private key: %v", tc.ID, skErr)
			}
			continue
		}

		checkMu(t, sk, tc)

		sig, err := signTestCase(sk, tc)

		if tc.Result == "invalid" {
			if err == nil {
				t.Errorf("%d: expected error", tc.ID)
			}
			continue
		}

		if err != nil {
			t.Errorf("%d: %v", tc.ID, err)
			continue
		}

		if !bytes.Equal(sig, tc.Sig) {
			t.Errorf("%d: signature does not match", tc.ID)
		}
	}
}

func runVerifyGroup(t *testing.T, scheme sign.Scheme, tg *TestGroup) {
	if tg.PrivateKey != nil || tg.PrivateSeed != nil {
		t.Fatal("Private key set")
	}
	if tg.PublicKey == nil {
		t.Fatal("Public key not set")
	}

	pk, pkErr := scheme.UnmarshalBinaryPublicKey(tg.PublicKey)

	for i := range tg.Tests {
		tc := &tg.Tests[i]

		if pkErr != nil {
			if tc.Result != "invalid" {
				t.Fatalf("%d: couldn't parse public key: %v", tc.ID, pkErr)
			}
			continue
		}

		ok := scheme.Verify(
			pk,
			tc.Msg,
			tc.Sig,
			&sign.SignatureOpts{Context: string(tc.Ctx)},
		)

		if ok != (tc.Result == "valid") {
			t.Errorf("%d: verification returned %v: %s", tc.ID, ok, tc.Comment)
		}
	}
}

func runTest(t *testing.T, name string) {
	raw, err := test.ReadGzip(path.Join(testDir, name))
	if err != nil {
		t.Fatalf("ReadGzip(): %v", err)
	}

	var ts TestSet
	if err := json.Unmarshal(raw, &ts); err != nil {
		t.Fatalf("json.Unmarshal(): %v", err)
	}

	scheme := ByName(ts.Algorithm)
	if scheme == nil {
		t.Fatalf("Can't find scheme %s", ts.Algorithm)
	}

	for i := range ts.TestGroups {
		tg := &ts.TestGroups[i]
		switch tg.Type {
		case "MlDsaSign":
			runSignGroup(t, scheme, tg)
		case "MlDsaVerify":
			runVerifyGroup(t, scheme, tg)
		default:
			t.Fatalf("Unknown test group type: %s", tg.Type)
		}
	}
}

func TestWycheproof(t *testing.T) {
	entries, err := os.ReadDir(testDir)
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json.gz") {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			runTest(t, entry.Name())
		})
	}
}
