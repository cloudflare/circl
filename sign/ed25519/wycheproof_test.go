package ed25519_test

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/sign/ed25519"
)

func hexStr2Key(k []byte, s string) bool {
	b, err := hex.DecodeString(s)
	if err != nil || len(k) != (len(s)/2) {
		return false
	}
	copy(k[:], b)
	return true
}

type group struct {
	Key struct {
		Curve string `json:"curve"`
		Size  int    `json:"keySize"`
		Pk    string `json:"pk"`
		Sk    string `json:"sk"`
		Type  string `json:"type"`
	} `json:"key"`
	Type  string `json:"type"`
	Tests []struct {
		TcID    int      `json:"tcId"`
		Comment string   `json:"comment"`
		Msg     string   `json:"msg"`
		Sig     string   `json:"sig"`
		Result  string   `json:"result"`
		Flags   []string `json:"flags"`
	} `json:"tests"`
}

type Wycheproof struct {
	Alg     string  `json:"algorithm"`
	Version string  `json:"generatorVersion"`
	Num     int     `json:"numberOfTests"`
	Groups  []group `json:"testGroups"`
}

func TestWycheproof(t *testing.T) {
	// Test vectors from Wycheproof v0.4.12
	const nameFile = "testdata/wycheproof_kat.json"
	jsonFile, err := os.Open(nameFile)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", nameFile, err)
	}
	defer jsonFile.Close()
	input, _ := ioutil.ReadAll(jsonFile)

	var kat Wycheproof
	err = json.Unmarshal(input, &kat)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", nameFile, err)
	}

	t.Run("EDDSAKeyPair", func(t *testing.T) {
		var private ed25519.PrivKey
		var want, got ed25519.PubKey
		for i, g := range kat.Groups {
			if g.Key.Curve != "edwards25519" {
				t.Errorf("Curve not expected %v", g.Key.Curve)
			}
			ok := hexStr2Key(private[:], g.Key.Sk) &&
				hexStr2Key(want[:], g.Key.Pk)
			ed25519.Pure{}.KeyGen(&got, &private)
			if got != want || !ok {
				test.ReportError(t, got, want, i, g.Key.Sk)
			}
		}
	})

	t.Run("EDDSAVer", func(t *testing.T) {
		var sig ed25519.Signature
		var private ed25519.PrivKey
		var public ed25519.PubKey

		for i, g := range kat.Groups {
			for _, gT := range g.Tests {
				msg := make([]byte, len(gT.Msg)/2)
				isValid := gT.Result == "valid"
				decoOK := hexStr2Key(private[:], g.Key.Sk) &&
					hexStr2Key(public[:], g.Key.Pk) &&
					hexStr2Key(sig[:], gT.Sig) &&
					hexStr2Key(msg[:], gT.Msg)

				if !decoOK && isValid {
					got := decoOK
					want := isValid
					test.ReportError(t, got, want, i, gT.TcID, gT.Result)
				}
				if isValid {
					got := ed25519.Pure{}.Sign(msg, &public, &private)
					want := sig
					if *got != want {
						test.ReportError(t, got, want, i, gT.TcID)
					}
				}
				got := ed25519.Pure{}.Verify(msg, &public, &sig)
				want := isValid
				if got != want {
					test.ReportError(t, got, want, i, gT.TcID)
				}
			}
		}
	})

}
