package ed25519

import (
	"archive/zip"
	"bufio"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func processRow(t *testing.T, line string, lineNum int) {
	var public PubKey
	var v struct {
		private   PrivKey
		public    PubKey
		message   []byte
		signature Signature
	}
	scheme := Pure{}
	values := strings.Split(line, ":")
	if len(values) != 5 {
		panic(fmt.Errorf("len: %v %v", len(values), values))
	}
	b, _ := hex.DecodeString(values[0])
	copy(v.private[:], b[:32])
	b, _ = hex.DecodeString(values[1])
	copy(v.public[:], b)
	v.message, _ = hex.DecodeString(values[2])
	b, _ = hex.DecodeString(values[3])
	copy(v.signature[:], b[:64])

	scheme.KeyGen(&public, &v.private)
	if public != v.public {
		got := public
		want := v.public
		test.ReportError(t, got, want, lineNum, v)
	}
	signature := scheme.Sign(v.message, &v.public, &v.private)
	if *signature != v.signature {
		got := *signature
		want := v.signature
		test.ReportError(t, got, want, lineNum, v)
	}
	got := scheme.Verify(v.message, &v.public, &v.signature)
	want := true
	if got != want {
		test.ReportError(t, got, want, lineNum, v)
	}
}

func TestRFC8032(t *testing.T) {
	const nameFile = "testdata/sign.input.zip"
	zipFile, err := zip.OpenReader(nameFile)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", nameFile, err)
	}
	defer zipFile.Close()

	for _, f := range zipFile.File {
		unzipped, err := f.Open()
		if err != nil {
			t.Fatalf("File %v can not be opened. Error: %v", f.Name, err)
		}
		defer unzipped.Close()

		fScanner := bufio.NewScanner(unzipped)
		for i := 1; fScanner.Scan(); i++ {
			processRow(t, fScanner.Text(), i)
		}
	}
}
