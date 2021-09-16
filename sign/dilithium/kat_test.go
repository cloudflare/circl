package dilithium

// Code to generate the NIST "PQCsignKAT" test vectors.
// See PQCsignKAT_sign.c and randombytes.c in the reference implementation.

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/nist"
)

func TestPQCgenKATSign(t *testing.T) {
	// Generated from reference implementation commit 61b51a71701b8ae9f546a1e5,
	// which can be found at https://github.com/pq-crystals/dilithium
	for _, tc := range []struct {
		name string
		want string
	}{
		{"Dilithium2", "38ed991c5ca11e39ab23945ca37af89e059d16c5474bf8ba96b15cb4e948af2a"},
		{"Dilithium3", "8196b32212753f525346201ffec1c7a0a852596fa0b57bd4e2746231dab44d55"},
		{"Dilithium5", "7ded97a6e6c809b43b54c248171d7504fa6a0cab651bf288bb00034782667481"},
		{"Dilithium2-AES", "b6673f8da5bba7dfae63adbbdf559f4fcfb715d1f91da98d4b52e26203d69196"},
		{"Dilithium3-AES", "482f4d672a9f1dc38cc8bcf8b1731b03fe99fcb6f2b73aa4a376b99faf89ccbe"},
		{"Dilithium5-AES", "54dfa85013d1b3da4f1d7c6dd270bc91a083cfece3d320c97906da125fd2a48f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode := ModeByName(tc.name)
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
			fmt.Fprintf(f, "# %s\n\n", tc.name)
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
				pk, sk := mode.NewKeyFromSeed(eseed[:])

				fmt.Fprintf(f, "pk = %X\n", pk.Bytes())
				fmt.Fprintf(f, "sk = %X\n", sk.Bytes())
				fmt.Fprintf(f, "smlen = %d\n", mlen+mode.SignatureSize())

				sig := mode.Sign(sk, msg[:])

				fmt.Fprintf(f, "sm = %X%X\n\n", sig, msg)

				if !mode.Verify(pk, msg[:], sig) {
					t.Fatal()
				}
			}
			if fmt.Sprintf("%x", f.Sum(nil)) != tc.want {
				t.Fatal()
			}
		})
	}
}
