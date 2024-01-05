package xwing

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/cloudflare/circl/internal/sha3"
)

func writeHex(w io.Writer, prefix string, val interface{}) {
	indent := "  "
	width := 74
	hex := fmt.Sprintf("%x", val)
	if len(prefix)+len(hex)+5 < width {
		fmt.Fprintf(w, "%s     %s\n", prefix, hex)
		return
	}
	fmt.Fprintf(w, "%s\n", prefix)
	for len(hex) != 0 {
		var toPrint string
		if len(hex) < width-len(indent) {
			toPrint = hex
			hex = ""
		} else {
			toPrint = hex[:width-len(indent)]
			hex = hex[width-len(indent):]
		}
		fmt.Fprintf(w, "%s%s\n", indent, toPrint)
	}
}

func TestVectors(t *testing.T) {
	h := sha3.NewShake128()
	w := new(bytes.Buffer)

	for i := 0; i < 3; i++ {
		var seed [SeedSize]byte
		_, _ = h.Read(seed[:])
		writeHex(w, "seed", seed)

		sk, pk := DeriveKeyPairPacked(seed[:])
		writeHex(w, "sk", sk)
		writeHex(w, "pk", pk)

		var eseed [EncapsulationSeedSize]byte
		_, _ = h.Read(eseed[:])
		writeHex(w, "eseed", eseed)

		ss, ct, err := Encapsulate(pk, eseed[:])
		if err != nil {
			t.Fatal(err)
		}
		writeHex(w, "ct", ct)
		writeHex(w, "ss", ss)

		ss2 := Decapsulate(ct, sk)
		if !bytes.Equal(ss, ss2) {
			t.Fatal()
		}

		fmt.Fprintf(w, "\n")
	}

	t.Logf("%s", w.String())
	h.Reset()
	_, _ = h.Write(w.Bytes())
	var cs [32]byte
	_, _ = h.Read(cs[:])
	got := fmt.Sprintf("%x", cs)

	// shake128 of spec/test-vectors.txt from X-Wing spec at
	// https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem
	want := "1bcd0057d861d6b866239936cadcaeee1ec0164dedc181c386e9e54fe46156fe"
	if got != want {
		t.Fatalf("%s ≠ %s", got, want)
	}
}
