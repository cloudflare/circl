package expander_test

import (
	"bytes"
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/cloudflare/circl/expander"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/xof"
)

func TestExpander(t *testing.T) {
	fileNames, err := filepath.Glob("./testdata/*.json")
	if err != nil {
		t.Fatal(err)
	}

	for _, fileName := range fileNames {
		f, err := os.Open(fileName)
		if err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(f)
		var v vectorExpanderSuite
		err = dec.Decode(&v)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()

		t.Run(v.Name+"/"+v.Hash, func(t *testing.T) { testExpander(t, &v) })
	}
}

func testExpander(t *testing.T, vs *vectorExpanderSuite) {
	var exp expander.Expander
	switch vs.Hash {
	case "SHA256":
		exp = expander.NewExpanderMD(crypto.SHA256, []byte(vs.DST))
	case "SHA512":
		exp = expander.NewExpanderMD(crypto.SHA512, []byte(vs.DST))
	case "SHAKE128":
		exp = expander.NewExpanderXOF(xof.SHAKE128, vs.K, []byte(vs.DST))
	case "SHAKE256":
		exp = expander.NewExpanderXOF(xof.SHAKE256, vs.K, []byte(vs.DST))
	default:
		t.Skip("hash not supported: " + vs.Hash)
	}

	for i, v := range vs.Tests {
		lenBytes, err := strconv.ParseUint(v.Len, 0, 64)
		if err != nil {
			t.Fatal(err)
		}

		got := exp.Expand([]byte(v.Msg), uint(lenBytes))
		want, err := hex.DecodeString(v.UniformBytes)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(got, want) {
			test.ReportError(t, got, want, i)
		}
	}
}

type vectorExpanderSuite struct {
	DST   string `json:"DST"`
	Hash  string `json:"hash"`
	Name  string `json:"name"`
	K     uint   `json:"k"`
	Tests []struct {
		DstPrime     string `json:"DST_prime"`
		Len          string `json:"len_in_bytes"`
		Msg          string `json:"msg"`
		MsgPrime     string `json:"msg_prime"`
		UniformBytes string `json:"uniform_bytes"`
	} `json:"tests"`
}

func BenchmarkExpander(b *testing.B) {
	in := []byte("input")
	dst := []byte("dst")

	for _, v := range []struct {
		Name string
		Exp  expander.Expander
	}{
		{"XMD", expander.NewExpanderMD(crypto.SHA256, dst)},
		{"XOF", expander.NewExpanderXOF(xof.SHAKE128, 0, dst)},
	} {
		exp := v.Exp
		for l := 8; l <= 10; l++ {
			max := int64(1) << uint(l)

			b.Run(fmt.Sprintf("%v/%v", v.Name, max), func(b *testing.B) {
				b.SetBytes(max)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					exp.Expand(in, uint(max))
				}
			})
		}
	}
}
