package xof_test

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/xof"
)

type vector struct {
	id      xof.ID
	in, out string
	outLen  int
}

var allVectors = []vector{
	{
		id:     xof.SHAKE128,
		in:     "",
		out:    "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
		outLen: 32,
	},
	{
		id:     xof.SHAKE256,
		in:     "",
		out:    "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
		outLen: 64,
	},
	{
		id:     xof.SHAKE128,
		in:     "The quick brown fox jumps over the lazy dog",
		out:    "f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e",
		outLen: 32,
	},
	{
		id:     xof.SHAKE128,
		in:     "The quick brown fox jumps over the lazy dof",
		out:    "853f4538be0db9621a6cea659a06c1107b1f83f02b13d18297bd39d7411cf10c",
		outLen: 32,
	},
	{
		id:     xof.BLAKE2XB,
		in:     "The quick brown fox jumps over the lazy dog",
		out:    "364e84ca4c103df292306c93ebba6f6633d5e9cc8a95e040498e9a012d5ca534",
		outLen: 32,
	},
	{
		id:     xof.BLAKE2XS,
		in:     "The quick brown fox jumps over the lazy dog",
		out:    "0650cde4df888a06eada0f0fecb3c17594304b4a03fdd678182f27db1238b174",
		outLen: 32,
	},
}

func TestXof(t *testing.T) {
	for i, v := range allVectors {
		X := v.id.New()
		_, err := X.Write([]byte(v.in))
		test.CheckNoErr(t, err, "error on xof.Write")

		got := make([]byte, v.outLen)
		want, _ := hex.DecodeString(v.out)

		for _, x := range []io.Reader{X, X.Clone()} {
			n, err := x.Read(got)
			test.CheckNoErr(t, err, "error on xof.Read")
			if n != v.outLen || !bytes.Equal(got, want) {
				test.ReportError(t, got, want, i, v.id)
			}
		}
	}

	err := test.CheckPanic(func() {
		var nonID xof.ID
		nonID.New()
	})
	test.CheckNoErr(t, err, "must panic")
}
