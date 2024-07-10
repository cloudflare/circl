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
		{"mceliece348864f", "d0d5ea348a181740862dcc8476ff7d00ce44d1c6e36b2145289d97f580f2cd7d"},
		{"mceliece348864", "76351ed2e95a616ca76230bac579cead21012d89181c7398381d0bbe904ab92c"},
		{"mceliece460896f", "552da50baff2666db7b64486c88da4e2b65b25c3d5424be682ca08ffce15a356"},
		{"mceliece460896", "fd785edfe1b721fb24fe159cb9f30cc17daec3d188d59a4bf47a83388880192e"},
		{"mceliece6688128f", "7b64c9882a00bc984e0ca9d3748d0b1bd9215d1bcf921643ee88d28d539303d8"},
		{"mceliece6688128", "3f926328959729c61a11b11ab6326246a42d9b3e76943bba2625342ea33723e2"},
		{"mceliece6960119f", "d6d3e929ff505108fd545d14df5f5bac234cd6d882f0eed3fd628f122e3093c6"},
		{"mceliece6960119", "e4d608fa9795c1a1704709ab9df3940ae1dbf0f708cc0dbdf76c8f3173088e46"},
		{"mceliece8192128f", "3fdb40d47705829c16de4fb5a81f7c095eb4dadc306cfc2c89eff2f483c42402"},
		{"mceliece8192128", "beb28fc0d1555a0028afeb6ebc72b8337f424a826be3d49b47759b8bda50db90"},
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

		g2.Fill(kseed)

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
