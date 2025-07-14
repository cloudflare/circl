package bls_test

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/sign/bls"
)

func TestVectors(t *testing.T) {
	// Test vectors taken from:
	// Repository:  https://github.com/kwantam/bls_sigs_ref/tree/sgn0_fix/test-vectors
	// Branch: sig0_fix
	// Path: /test-vectors/sig_[g1|g2]_basic/[name]
	// Compression: zip

	for _, name := range []string{"P256", "P521"} {
		t.Run(name+"/G1", func(t *testing.T) { testVector[bls.KeyG2SigG1](t, "g1", name) })
		t.Run(name+"/G2", func(t *testing.T) { testVector[bls.KeyG1SigG2](t, "g2", name) })
	}
}

func testVector[K bls.KeyGroup](t *testing.T, group, name string) {
	fileName := fmt.Sprintf("./testdata/sig_%v_basic_%v.txt.gz", group, name)
	input, err := test.ReadGzip(fileName)
	if err != nil {
		t.Fatalf("File %v can not be read. Error: %v", fileName, err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(input))
	for scanner.Scan() {
		line := scanner.Text()
		inputs := strings.Split(line, " ")
		if len(inputs) != 3 {
			t.Fatalf("bad input length")
		}

		msg, err := hex.DecodeString(inputs[0])
		test.CheckNoErr(t, err, "error decoding msg")
		seed, err := hex.DecodeString(inputs[1])
		test.CheckNoErr(t, err, "error decoding sk")
		wantSig := inputs[2]

		salt := []byte("BLS-SIG-KEYGEN-SALT-")
		keyInfo := []byte("")
		priv, err := bls.KeyGen[K](seed, salt, keyInfo)
		test.CheckNoErr(t, err, "error generating priv key")

		sig := bls.Sign(priv, msg)
		gotSig := hex.EncodeToString(sig)

		if gotSig != wantSig {
			test.ReportError(t, gotSig, wantSig, msg)
		}

		pub := priv.PublicKey()
		test.CheckOk(bls.Verify(pub, msg, sig), "cannot verify", t)
	}
}
