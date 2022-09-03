package ed25519_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/sign/ed25519"
)

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

func (kat *Wycheproof) readFile(t *testing.T, fileName string) {
	jsonFile, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", fileName, err)
	}
	defer jsonFile.Close()
	input, err := io.ReadAll(jsonFile)
	if err != nil {
		t.Fatalf("File %v can not be read. Error: %v", fileName, err)
	}

	err = json.Unmarshal(input, &kat)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", fileName, err)
	}
}

func (kat *Wycheproof) keyPair(t *testing.T) {
	for i, g := range kat.Groups {
		if g.Key.Curve != "edwards25519" {
			t.Errorf("Curve not expected %v", g.Key.Curve)
		}
		private, _ := hex.DecodeString(g.Key.Sk)
		public, _ := hex.DecodeString(g.Key.Pk)
		keys := ed25519.NewKeyFromSeed(private)
		got := keys.Public().(ed25519.PublicKey)
		want := public

		if !bytes.Equal(got, want) {
			test.ReportError(t, got, want, i, g.Key.Sk)
		}
	}
}

func (kat *Wycheproof) verify(t *testing.T) {
	for i, g := range kat.Groups {
		for _, gT := range g.Tests {
			isValid := gT.Result == "valid"
			private, _ := hex.DecodeString(g.Key.Sk)
			public, _ := hex.DecodeString(g.Key.Pk)
			sig, _ := hex.DecodeString(gT.Sig)
			msg, _ := hex.DecodeString(gT.Msg)

			priv := ed25519.NewKeyFromSeed(private)
			got := priv.Public().(ed25519.PublicKey)
			want := public
			if !bytes.Equal(got, want) {
				test.ReportError(t, got, want, i, gT.TcID)
			}
			if isValid {
				got := ed25519.Sign(priv, msg)
				want := sig
				if !bytes.Equal(got, want) {
					test.ReportError(t, got, want, i, gT.TcID)
				}
			}
			{
				got := ed25519.Verify(priv.Public().(ed25519.PublicKey), msg, sig)
				want := isValid
				if got != want {
					test.ReportError(t, got, want, i, gT.TcID)
				}
			}
		}
	}
}

func TestWycheproof(t *testing.T) {
	// Test vectors from Wycheproof v0.4.12
	var kat Wycheproof
	kat.readFile(t, "testdata/wycheproof_Ed25519.json")
	t.Run("EDDSAKeyPair", kat.keyPair)
	t.Run("EDDSAVerify", kat.verify)
}
