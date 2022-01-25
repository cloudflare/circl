package frodo

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
	kats := []struct {
		name string
		want string
	}{
		// Computed from:
		// https://github.com/microsoft/PQCrypto-LWEKE/blob/66fc7744c3aae6acfc5fcc587ec7f2cdec48d216/KAT/PQCkemKAT_19888_shake.rsp
		{"FrodoKEM-640-SHAKE", "604a10cfc871dfaed9cb5b057c644ab03b16852cea7f39bc7f9831513b5b1cfa"},
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

		g2.Fill(kseed[:])

		pk, sk := scheme.DeriveKeyPair(kseed)
		ppk, _ := pk.MarshalBinary()
		psk, _ := sk.MarshalBinary()

		g2.Fill(eseed)
		ct, ss, err := scheme.EncapsulateDeterministically(pk, eseed)
		if err != nil {
			t.Fatal(err)
		}
		ss2, _ := scheme.Decapsulate(sk, ct)
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
