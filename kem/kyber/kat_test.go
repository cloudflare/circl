package kyber

// Code to generate the NIST "PQCsignKAT" test vectors.
// See PQCsignKAT_sign.c and randombytes.c in the reference implementation.

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/nist"
	"github.com/cloudflare/circl/kem/schemes"
)

func TestPQCgenKATKem(t *testing.T) {
	// Computed from reference implementation
	testPQCgenKATKem(t, "Kyber1024", "9e6441f6f77cd33ba2b7e1324ec66e7623808fe91896e7f06ee054e3a8645e93")
	testPQCgenKATKem(t, "Kyber768", "6a9a983f3a003117c00f2adf8a1b42692429d40fd99ad12462caeb48e737a6eb")
	testPQCgenKATKem(t, "Kyber512", "0da040de6aa757004315e18bfca4f25f6f9cd86e676bc87feb44cd87f3687db8")
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
	fmt.Fprintf(f, "# %s\n\n", name)
	for i := 0; i < 100; i++ {
		g.Fill(seed[:])
		fmt.Fprintf(f, "count = %d\n", i)
		fmt.Fprintf(f, "seed = %X\n", seed)
		g2 := nist.NewDRBG(&seed)

		// This is not equivalent to g2.Fill(kseed[:]).  As the reference
		// implementation calls randombytes twice generating the keypair,
		// we have to do that as well.
		g2.Fill(kseed[:32])
		g2.Fill(kseed[32:])

		g2.Fill(eseed)
		pk, sk := scheme.DeriveKey(kseed)
		ppk, _ := pk.MarshalBinary()
		psk, _ := sk.MarshalBinary()
		ct, ss := scheme.EncapsulateDeterministically(pk, eseed)
		ss2 := scheme.Decapsulate(sk, ct)
		if !bytes.Equal(ss, ss2) {
			t.Fatal()
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
