package kyber

// Code to generate the NIST "PQCsignKAT" test vectors.
// See PQCsignKAT_sign.c and randombytes.c in the reference implementation.

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
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
		{"Kyber1024", "89248f2f33f7f4f7051729111f3049c409a933ec904aedadf035f30fa5646cd5"},
		{"Kyber768", "a1e122cad3c24bc51622e4c242d8b8acbcd3f618fee4220400605ca8f9ea02c2"},
		{"Kyber512", "e9c2bd37133fcb40772f81559f14b1f58dccd1c816701be9ba6214d43baf4547"},

		// TODO crossreference with standard branch of reference implementation
		// 		once they've added the final change: domain separation in K-PKE.KeyGen().
		{"ML-KEM-512", "a30184edee53b3b009356e1e31d7f9e93ce82550e3c622d7192e387b0cc84f2e"},
		{"ML-KEM-768", "729367b590637f4a93c68d5e4a4d2e2b4454842a52c9eec503e3a0d24cb66471"},
		{"ML-KEM-1024", "3fba7327d0320cb6134badf2a1bcb963a5b3c0026c7dece8f00d6a6155e47b33"},
	}
	for _, kat := range kats {
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
	eseed := make([]byte, scheme.EncapsulationSeedSize())
	for i := 0; i < 48; i++ {
		seed[i] = byte(i)
	}
	f := sha256.New()
	g := nist.NewDRBG(&seed)

	// The "standard" branch reference implementation still uses Kyber
	// as name instead of ML-KEM.
	mustWrite(t, f, "# %s\n\n", strings.ReplaceAll(name, "ML-KEM-", "Kyber"))
	for i := 0; i < 100; i++ {
		g.Fill(seed[:])
		mustWrite(t, f, "count = %d\n", i)
		mustWrite(t, f, "seed = %X\n", seed)
		g2 := nist.NewDRBG(&seed)

		if strings.HasPrefix(name, "ML-KEM") {
			// https://github.com/pq-crystals/kyber/commit/830e0ba1a7fdba6cde03f8139b0d41ad2102b860
			g2.Fill(kseed[:])
		} else {
			// This is not equivalent to g2.Fill(kseed[:]).  As the reference
			// implementation calls randombytes twice generating the keypair,
			// we have to do that as well.
			g2.Fill(kseed[:32])
			g2.Fill(kseed[32:])
		}

		g2.Fill(eseed)
		pk, sk := scheme.DeriveKeyPair(kseed)
		ppk, _ := pk.MarshalBinary()
		psk, _ := sk.MarshalBinary()
		ct, ss, _ := scheme.EncapsulateDeterministically(pk, eseed)
		ss2, _ := scheme.Decapsulate(sk, ct)
		if !bytes.Equal(ss, ss2) {
			t.Fatal()
		}
		mustWrite(t, f, "pk = %X\n", ppk)
		mustWrite(t, f, "sk = %X\n", psk)
		mustWrite(t, f, "ct = %X\n", ct)
		mustWrite(t, f, "ss = %X\n\n", ss)
	}
	if fmt.Sprintf("%x", f.Sum(nil)) != expected {
		t.Fatalf("%s %x %s", name, f.Sum(nil), expected)
	}
}

func mustWrite(t *testing.T, f io.Writer, format string, data any) {
	_, err := fmt.Fprintf(f, format, data)
	test.CheckNoErr(t, err, "fprintf failed")
}
