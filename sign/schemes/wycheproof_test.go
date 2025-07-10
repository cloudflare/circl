package schemes

import (
	"bytes"
	"encoding/json"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/sign"
)

const testDir = "testdata/wycheproof"

type Test struct {
	Msg     test.HexBytes `json:"msg"`
	Sig     test.HexBytes `json:"sig"`
	Result  string        `json:"result"`
	Ctx     test.HexBytes `json:"ctx"`
	ID      int           `json:"tcId"`
	Comment string        `json:"comment"`
}

type TestGroup struct {
	PrivateKey  test.HexBytes `json:"privateKey"`
	PrivateSeed test.HexBytes `json:"privateSeed"`
	PublicKey   test.HexBytes `json:"publicKey"`
	Tests       []Test         `json:"tests"`
	Type        string         `json:"type"`
}

type TestSet struct {
	Algorithm  string      `json:"algorithm"`
	TestGroups []TestGroup `json:"testGroups"`
}

//nolint:gocyclo
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

	for _, tg := range ts.TestGroups {
		switch tg.Type {
		case "MlDsaSign":
			var sk sign.PrivateKey
			var skErr error
			if tg.PrivateKey == nil && tg.PrivateSeed == nil {
				t.Fatal("Neither private key or seed are set")
			}
			if tg.PrivateKey != nil && tg.PrivateSeed != nil {
				t.Fatal("Both private key and seed are set")
			}
			if tg.PublicKey != nil {
				t.Fatal("public key set")
			}
			if tg.PrivateSeed != nil {
				_, sk = scheme.DeriveKey(tg.PrivateSeed)
			} else {
				sk, skErr = scheme.UnmarshalBinaryPrivateKey(tg.PrivateKey)
			}
			for _, tc := range tg.Tests {
				// TODO The standards don't require rejecting private keys
				// 		with out of range s1/s2. Pending discussion on whether
				//      we should reject them, we're skipping these testcases.
				if tc.Comment == "private key with s1 vector out of range" ||
					tc.Comment == "private key with s2 vector out of range" {
					continue
				}

				if sk == nil {
					if tc.Result == "invalid" { //nolint:goconst
						continue
					}
					t.Fatalf("Couldn't parse private key: %v", skErr)
				}

				sig, err := calmSign(
					scheme,
					sk,
					tc.Msg,
					&sign.SignatureOpts{Context: string(tc.Ctx)},
				)

				if tc.Result == "invalid" {
					if err == nil {
						t.Fatalf("Expected error %v", tc.ID)
					}
					continue
				}

				if err != nil || skErr != nil {
					t.Fatalf("Unexpected panic: %v", err)
				}

				if !bytes.Equal(sig, tc.Sig) {
					t.Fatalf("Signature did not match: %v %v", sig, tc.Sig)
				}
			}
		case "MlDsaVerify":
			var pk sign.PublicKey
			var pkErr error
			if tg.PrivateKey != nil || tg.PrivateSeed != nil {
				t.Fatal("Private key set")
			}
			if tg.PublicKey == nil {
				t.Fatal("Public key not set")
			}
			pk, pkErr = scheme.UnmarshalBinaryPublicKey(tg.PublicKey)
			for _, tc := range tg.Tests {
				if pk == nil {
					if tc.Result == "invalid" {
						continue
					}
					t.Fatalf("Couldn't parse private key: %v", pkErr)
				}

				ok := scheme.Verify(
					pk,
					tc.Msg,
					tc.Sig,
					&sign.SignatureOpts{Context: string(tc.Ctx)},
				)

				if tc.Result == "invalid" {
					if ok {
						t.Fatalf("Expected failure %d", tc.ID)
					}
					continue
				}

				if !ok {
					t.Fatal("expected success")
				}
			}
		default:
			t.Fatalf("Unknown test group type: %s", tg.Type)
		}
	}
}

func calmSign(scheme sign.Scheme, sk sign.PrivateKey,
	msg []byte, opts *sign.SignatureOpts,
) (sig []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()
	sig = scheme.Sign(sk, msg, opts)
	return
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
