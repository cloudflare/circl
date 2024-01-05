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
	if len(prefix)+len(hex)+1 < width {
		fmt.Fprintf(w, "%s %s\n", prefix, hex)
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
		writeHex(w, "seed  ", seed)

		sk, pk := DeriveKeyPairPacked(seed[:])
		writeHex(w, "sk    ", sk)
		writeHex(w, "pk    ", pk)

		var eseed [EncapsulationSeedSize]byte
		_, _ = h.Read(eseed[:])
		writeHex(w, "eseed ", eseed)

		ss, ct := Encapsulate(pk, eseed[:])
		writeHex(w, "ct    ", ct)
		writeHex(w, "ss    ", ss)

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
	want := "dff9d6258b66060ac402a8faa0114d6a8b683bfa8555eb630b764f2a3a709990"
	if got != want {
		t.Fatalf("%s ≠ %s", got, want)
	}
}
