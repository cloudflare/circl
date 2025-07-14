package ed25519_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/sign/ed25519"
)

type group struct {
	Key struct {
		Curve string        `json:"curve"`
		Size  int           `json:"keySize"`
		Pk    test.HexBytes `json:"pk"`
		Sk    test.HexBytes `json:"sk"`
		Type  string        `json:"type"`
	} `json:"key"`
	Type  string `json:"type"`
	Tests []struct {
		TcID    int           `json:"tcId"`
		Comment string        `json:"comment"`
		Msg     test.HexBytes `json:"msg"`
		Sig     test.HexBytes `json:"sig"`
		Result  string        `json:"result"`
		Flags   []string      `json:"flags"`
	} `json:"tests"`
}

type Wycheproof struct {
	Alg     string  `json:"algorithm"`
	Version string  `json:"generatorVersion"`
	Num     int     `json:"numberOfTests"`
	Groups  []group `json:"testGroups"`
}

func (kat *Wycheproof) readFile(t *testing.T, fileName string) {
	input, err := test.ReadGzip(fileName)
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
		keys := ed25519.NewKeyFromSeed(g.Key.Sk)
		got := keys.Public().(ed25519.PublicKey)
		want := g.Key.Pk

		if !bytes.Equal(got, want) {
			test.ReportError(t, got, want, i, g.Key.Sk)
		}
	}
}

func (kat *Wycheproof) verify(t *testing.T) {
	for i, g := range kat.Groups {
		for _, gT := range g.Tests {
			isValid := gT.Result == "valid"

			priv := ed25519.NewKeyFromSeed(g.Key.Sk)
			got := priv.Public().(ed25519.PublicKey)
			want := g.Key.Pk
			if !bytes.Equal(got, want) {
				test.ReportError(t, got, want, i, gT.TcID)
			}
			if isValid {
				got := ed25519.Sign(priv, gT.Msg)
				want := gT.Sig
				if !bytes.Equal(got, want) {
					test.ReportError(t, got, want, i, gT.TcID)
				}
			}
			{
				got := ed25519.Verify(priv.Public().(ed25519.PublicKey), gT.Msg, gT.Sig)
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
	kat.readFile(t, "testdata/wycheproof_Ed25519.json.gz")
	t.Run("EDDSAKeyPair", kat.keyPair)
	t.Run("EDDSAVerify", kat.verify)
}
