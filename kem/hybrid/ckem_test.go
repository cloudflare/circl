package hybrid

import (
	"bytes"
	"crypto/ecdh"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

// DeriveKeyPair once read its seed through crypto/ecdh's GenerateKey, which
// may consume an extra byte of the reader, so one seed gave different keys.
func TestCSchemeDeriveKeyPairDeterministic(t *testing.T) {
	for _, sch := range []cScheme{{ecdh.P256()}, {ecdh.P384()}, {ecdh.P521()}} {
		t.Run(sch.Name(), func(t *testing.T) {
			seed := bytes.Repeat([]byte{0x5a}, sch.SeedSize())
			pk, sk := sch.DeriveKeyPair(seed)
			want, err := pk.MarshalBinary()
			test.CheckNoErr(t, err, "marshaling the derived public key failed")
			wantSK, err := sk.MarshalBinary()
			test.CheckNoErr(t, err, "marshaling the derived private key failed")
			test.CheckOk(len(want) == sch.PublicKeySize(), "wrong public key size", t)
			test.CheckOk(len(wantSK) == sch.PrivateKeySize(), "wrong private key size", t)

			for i := range 32 {
				pkI, skI := sch.DeriveKeyPair(seed)
				gotPK, errPK := pkI.MarshalBinary()
				test.CheckNoErr(t, errPK, "marshaling the derived public key failed")
				gotSK, errSK := skI.MarshalBinary()
				test.CheckNoErr(t, errSK, "marshaling the derived private key failed")
				if !bytes.Equal(want, gotPK) || !bytes.Equal(wantSK, gotSK) {
					t.Fatalf("derivation %d from one seed gave a different key pair", i)
				}
			}

			pkOther, _ := sch.DeriveKeyPair(bytes.Repeat([]byte{0x5b}, sch.SeedSize()))
			other, err := pkOther.MarshalBinary()
			test.CheckNoErr(t, err, "marshaling the derived public key failed")
			test.CheckOk(!bytes.Equal(want, other), "different seeds gave the same key", t)
		})
	}
}

func TestCSchemeEncapsulateDeterministically(t *testing.T) {
	sch := cScheme{ecdh.P256()}
	pk, _ := sch.DeriveKeyPair(bytes.Repeat([]byte{0x11}, sch.SeedSize()))
	seed := bytes.Repeat([]byte{0x22}, sch.EncapsulationSeedSize())
	wantCT, wantSS, err := sch.EncapsulateDeterministically(pk, seed)
	test.CheckNoErr(t, err, "EncapsulateDeterministically failed")
	for i := range 32 {
		ct, ss, errI := sch.EncapsulateDeterministically(pk, seed)
		test.CheckNoErr(t, errI, "EncapsulateDeterministically failed")
		if !bytes.Equal(wantCT, ct) || !bytes.Equal(wantSS, ss) {
			t.Fatalf("encapsulation %d from one seed gave a different ciphertext", i)
		}
	}
}
