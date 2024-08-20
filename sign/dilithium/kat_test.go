package dilithium

// Code to generate the NIST "PQCsignKAT" test vectors.
// See PQCsignKAT_sign.c and randombytes.c in the reference implementation.

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/cloudflare/circl/internal/nist"
	"github.com/cloudflare/circl/sign/schemes"
)

func TestPQCgenKATSign(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
	}{
		// Generated from reference implementation commit 61b51a71701b8ae9f546a1e5,
		// which can be found at https://github.com/pq-crystals/dilithium
		{"Dilithium2", "38ed991c5ca11e39ab23945ca37af89e059d16c5474bf8ba96b15cb4e948af2a"},
		{"Dilithium3", "8196b32212753f525346201ffec1c7a0a852596fa0b57bd4e2746231dab44d55"},
		{"Dilithium5", "7ded97a6e6c809b43b54c248171d7504fa6a0cab651bf288bb00034782667481"},

		// TODO Update to final FIPS 204 standard. Test vectors below are for the IPD.
		//
		// Generated from reference implementation commit e7bed6258b9a3703ce78d4ec3,
		// which can be found on the standard branch
		// of https://github.com/pq-crystals/dilithium
		// {"ML-DSA-44", "4657f244d1204e5847b3cacea4fc6116579571bee8ac89b8cba6771f303ee260"},
		// {"ML-DSA-65", "99a95d7ef804020a666f455c5003232d0c0200dfc4f5df85dceb8f56256dcba8"},
		// {"ML-DSA-87", "3377835fffb7cf9aac52947225c8974335bc05532ddf672a8b706ab8991435a2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode := schemes.ByName(tc.name)
			if mode == nil {
				t.Fatal()
			}

			var seed [48]byte
			var eseed [32]byte
			for i := 0; i < 48; i++ {
				seed[i] = byte(i)
			}
			f := sha256.New()
			g := nist.NewDRBG(&seed)
			nameInKat := tc.name
			if !strings.HasPrefix(tc.name, "Dilithium") {
				switch tc.name {
				case "ML-DSA-44":
					nameInKat = "Dilithium2"
				case "ML-DSA-65":
					nameInKat = "Dilithium3"
				case "ML-DSA-87":
					nameInKat = "Dilithium5"
				}
			}
			fmt.Fprintf(f, "# %s\n\n", nameInKat)
			for i := 0; i < 100; i++ {
				mlen := 33 * (i + 1)
				g.Fill(seed[:])
				msg := make([]byte, mlen)
				g.Fill(msg[:])

				fmt.Fprintf(f, "count = %d\n", i)
				fmt.Fprintf(f, "seed = %X\n", seed)
				fmt.Fprintf(f, "mlen = %d\n", mlen)
				fmt.Fprintf(f, "msg = %X\n", msg)

				g2 := nist.NewDRBG(&seed)
				g2.Fill(eseed[:])
				pk, sk := mode.DeriveKey(eseed[:])

				ppk, err := pk.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				psk, err := sk.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}

				fmt.Fprintf(f, "pk = %X\n", ppk)
				fmt.Fprintf(f, "sk = %X\n", psk)
				fmt.Fprintf(f, "smlen = %d\n", mlen+mode.SignatureSize())

				sig := mode.Sign(sk, msg[:], nil)

				fmt.Fprintf(f, "sm = %X%X\n\n", sig, msg)

				if !mode.Verify(pk, msg[:], sig, nil) {
					t.Fatal()
				}
			}
			if fmt.Sprintf("%x", f.Sum(nil)) != tc.want {
				t.Fatal()
			}
		})
	}
}
