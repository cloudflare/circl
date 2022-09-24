package mceliece

// Code to generate the NIST "PQCsignKAT" test vectors.
// See PQCsignKAT_sign.c and randombytes.c in the reference implementation.

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/nist"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/kem/schemes"
)

func TestPQCgenKATKem(t *testing.T) {
	kats := []struct {
		name string
		want string
	}{
		// Computed from reference implementation
		{"mceliece348864", "083224b827fc165a0f0e395e1905d7056ca309bf88a84c9b21ca658eddcbf140"},
		{"mceliece348864f", "0846f26726d7b3bdf6fa68c886ed2079890714a7ffb4923ba8508aad93505a86"},
		{"mceliece460896", "ef97c4eaf801982a5acd253f012eafc10d92034f5ec92e097a71e1ae860b26ae"},
		{"mceliece460896f", "c7feca45bbeeaa6c3969f1344f8cfff3e6b09b5c7c642ff5d76f51cfbf8ddd90"},
		{"mceliece6688128", "ed7e195667f6d56f0ec33917edf5bdb2902b61f50761ca2ef17be2721365fb9a"},
		{"mceliece6688128f", "fa3e762d466b1f39850c2b543dc3d38714c28ecc096d5ba2fa07a9d8ac6910b1"},
		{"mceliece6960119", "99dbab3fe1bed15c6707888d6cac01f3f7fe35302536e6403975f6044059df29"},
		{"mceliece6960119f", "56a1bccbc9c1197476f3bb55d31b7a41794134ed68977a756dba9e6125c4d104"},
		{"mceliece8192128", "1208af7d036c256eb0d373e237a0b74c2aae22e9724c2d230c6f1072ebab20c0"},
		{"mceliece8192128f", "66566cb42f443adf8c60d2f9ec8551996746819874cd4bb7fd85701bbe8f73b1"},
	}

	for _, kat := range kats {
		kat := kat
		t.Run(kat.name, func(t *testing.T) {
			testPQCgenKATKem(t, kat.name, kat.want)
		})
	}
}

func testPQCgenKATKem(t *testing.T, name, expected string) {
	scheme := schemes.ByName(name)
	if scheme == nil {
		t.Fatal()
	}

	var seed [48]byte
	kseed := make([]byte, scheme.SeedSize())
	for i := 0; i < 48; i++ {
		seed[i] = byte(i)
	}
	f := sha256.New()
	g := nist.NewDRBG(&seed)
	fmt.Fprintf(f, "# kem/%s\n\n", name)
	for i := 0; i < 10; i++ {
		g.Fill(seed[:])
		fmt.Fprintf(f, "count = %d\n", i)
		fmt.Fprintf(f, "seed = %X\n", seed)

		g2 := nist.NewDRBG(&seed)

		// This is not equivalent to g2.Fill(kseed[:]).  As the reference
		// implementation calls randombytes twice generating the keypair,
		// we have to do that as well.
		g2.Fill(kseed[:32])

		pk, sk := scheme.DeriveKeyPair(kseed)
		ppk, _ := pk.MarshalBinary()
		psk, _ := sk.MarshalBinary()
		ct, ss, err := scheme.EncapsulateDeterministically(pk, seed[:])
		if err != nil {
			t.Fatal(err)
		}
		ss2, err := scheme.Decapsulate(sk, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ss, ss2) {
			test.ReportError(t, fmt.Sprintf("%X", ss2), fmt.Sprintf("%X", ss))
		}
		fmt.Fprintf(f, "pk = %X\n", ppk)
		fmt.Fprintf(f, "sk = %X\n", psk)
		fmt.Fprintf(f, "ct = %X\n", ct)
		fmt.Fprintf(f, "ss = %X\n\n", ss)
	}
	if fmt.Sprintf("%x", f.Sum(nil)) != expected {
		t.Fatal()
	}
}
